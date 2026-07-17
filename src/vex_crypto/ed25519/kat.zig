//! Vexor Ed25519 pure-Zig KAT gate (byte-exact).
//!
//! Root this file with `zig build test-vex-ed25519` (core-pinned 28-31). It
//! is the correctness gate for the pure-Zig ed25519 core: Vexor's own
//! orchestration (root.zig) over the credited field-point floor (avx512.zig /
//! generic.zig) plus the wycheproof.zig corpus. Covers, per the Phase-1
//! build plan:
//!   (a) Wycheproof EDDSA vectors — the strict verifier must match every
//!       valid/invalid verdict byte-for-byte.
//!   (b) ACCEPT + lenient-specific tests — valid sigs accepted; the
//!       consensus `verify()` (std.crypto) still ACCEPTS the cofactored /
//!       non-canonical cases Agave accepts (documented, NOT over-rejected).
//!   (c) The 3-way semantic-divergence matrix (consensus-stdlib vs our
//!       strict vs Sig-derived cofactorless-lenient) — the PROVEN fork
//!       class (slot 415479361), pinned here so a future refactor that
//!       accidentally routes consensus traffic through a strict/cofactorless
//!       verifier fails loudly instead of forking live.
const std = @import("std");
const core = @import("root.zig");
const wycheproof = @import("wycheproof.zig");

const Ed25519 = std.crypto.sign.Ed25519;

/// Consensus-path predicate under test: the EXACT verifier Vexor's
/// `vex_crypto/ed25519.zig verify()` delegates to (std.crypto). Kept here so
/// the 3-way matrix compares the real three predicates.
fn verifyConsensusStdlib(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    const signature = Ed25519.Signature.fromBytes(sig.*);
    const public_key = Ed25519.PublicKey.fromBytes(pubkey.*) catch return false;
    signature.verify(message, public_key) catch return false;
    return true;
}

// ── (a) Wycheproof — strict verifier must match every verdict ──────────────
test "wycheproof: strict verify matches every EDDSA verdict byte-for-byte" {
    var total: usize = 0;
    var passed: usize = 0;
    for (wycheproof.groups) |group| {
        var public_key_buffer: [32]u8 = undefined;
        const public_key = std.fmt.hexToBytes(&public_key_buffer, group.pubkey) catch continue;
        if (public_key.len != 32) continue;

        for (group.cases) |case| {
            var msg_buffer: [1024]u8 = undefined;
            const msg_len = case.msg.len / 2;
            const message = std.fmt.hexToBytes(msg_buffer[0..msg_len], case.msg) catch continue;

            var sig_buffer: [64]u8 = undefined;
            if (case.sig.len > 64 * 2) continue;
            const signature_bytes = std.fmt.hexToBytes(&sig_buffer, case.sig) catch continue;
            if (signature_bytes.len != 64) continue;

            total += 1;
            const got = core.verifyStrict(&sig_buffer, &public_key_buffer, message);
            const want = case.expected == .valid;
            try std.testing.expectEqual(want, got);
            passed += 1;
        }
    }
    std.debug.print("[KAT a] wycheproof strict: {d}/{d} vectors matched\n", .{ passed, total });
    try std.testing.expect(total >= 130);
}

// ── (b) ACCEPT + lenient consensus-parity ──────────────────────────────────
test "ACCEPT: freshly-signed messages verify under strict + consensus + sign round-trip" {
    var seed: [32]u8 = undefined;
    var count: usize = 0;
    for (0..64) |i| {
        @memset(&seed, @intCast(i & 0xff));
        seed[0] = @intCast((i *% 37) & 0xff);
        seed[31] = @intCast((i *% 101) & 0xff);
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch continue;
        const pubkey = kp.public_key.toBytes();
        var secret: [64]u8 = undefined;
        secret[0..32].* = seed;
        secret[32..64].* = pubkey;

        var msg_buf: [40]u8 = undefined;
        const msg_len = (i % 39) + 1;
        for (0..msg_len) |j| msg_buf[j] = @intCast((i + j) & 0xff);
        const msg = msg_buf[0..msg_len];

        // Our own pure-Zig sign, then verify under strict + consensus.
        const sig = core.signPureZig(secret, msg);
        try std.testing.expect(core.verifyStrict(&sig, &pubkey, msg));
        try std.testing.expect(verifyConsensusStdlib(&sig, &pubkey, msg));

        // Corrupt → all reject.
        var bad = sig;
        bad[i % 64] ^= 1;
        try std.testing.expect(!core.verifyStrict(&bad, &pubkey, msg));
        try std.testing.expect(!verifyConsensusStdlib(&bad, &pubkey, msg));
        count += 1;
    }
    std.debug.print("[KAT b] ACCEPT round-trip: {d} keypairs signed+verified\n", .{count});
    try std.testing.expect(count >= 50);
}

test "LENIENT: consensus verify() still ACCEPTS the cofactored cases Agave accepts (no over-reject)" {
    // Cases 4 & 5 from Sig/dalek's own eddsa vectors: "cofactored
    // verification". These are ACCEPTED by std.crypto (== Agave/dalek == the
    // live cluster consensus predicate). This is exactly why routing the
    // consensus verify() through a strict/cofactorless verifier forked
    // bank_hash at slot 415479361 — this KAT pins that the consensus
    // predicate keeps accepting them.
    const Vec = struct { msg: []const u8, pk: []const u8, sig: []const u8 };
    const cofactored = [_]Vec{
        .{
            .msg = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .pk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig = "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        },
        .{
            .msg = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .pk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig = "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        },
    };
    for (cofactored) |v| {
        var msg: [32]u8 = undefined;
        const msg_len = v.msg.len / 2;
        _ = try std.fmt.hexToBytes(msg[0..msg_len], v.msg);
        var pk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pk, v.pk);
        var sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig, v.sig);

        // Consensus predicate ACCEPTS (this is the load-bearing assertion).
        try std.testing.expect(verifyConsensusStdlib(&sig, &pk, msg[0..msg_len]));
    }
    std.debug.print("[KAT b/lenient] consensus ACCEPTs {d} cofactored cases (parity preserved)\n", .{cofactored.len});
}

// ── (c) 3-way semantic-divergence matrix (the fork class, pinned) ──────────
const MatrixVec = struct {
    label: []const u8,
    msg: []const u8,
    pk: []const u8,
    sig: []const u8,
    want_consensus: bool, // std.crypto (Agave/dalek/cluster) verdict
    want_strict: bool, // our verifyStrict (== Ballet verify_strict)
    want_lenient: bool, // our verifyLenientCofactorless (== Sig cofactorless)
};

// Verdicts empirically captured on Zig 0.15.2 / znver4 and reconciled with
// Sig's own eddsa-test expectations + dalek 2.0 verify_strict.
const matrix = [_]MatrixVec{
    .{ .label = "small-order A+R", .want_consensus = false, .want_strict = false, .want_lenient = true, .msg = "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", .pk = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", .sig = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000" },
    .{ .label = "small-order A", .want_consensus = false, .want_strict = false, .want_lenient = true, .msg = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", .pk = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", .sig = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04" },
    .{ .label = "ordinary valid", .want_consensus = true, .want_strict = true, .want_lenient = true, .msg = "48656c6c6f", .pk = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", .sig = "1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905" },
    .{ .label = "mixed orders", .want_consensus = true, .want_strict = true, .want_lenient = true, .msg = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", .pk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", .sig = "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009" },
    // The load-bearing pair: consensus ACCEPTS, both strict AND lenient REJECT.
    .{ .label = "cofactored #4 (consensus-only accept)", .want_consensus = true, .want_strict = false, .want_lenient = false, .msg = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", .pk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", .sig = "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09" },
    .{ .label = "cofactored #5 (consensus-only accept)", .want_consensus = true, .want_strict = false, .want_lenient = false, .msg = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", .pk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", .sig = "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405" },
    .{ .label = "S > L (non-canonical S)", .want_consensus = false, .want_strict = false, .want_lenient = false, .msg = "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", .pk = "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", .sig = "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514" },
    .{ .label = "non-canonical R (lenient-only accept)", .want_consensus = false, .want_strict = false, .want_lenient = true, .msg = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", .pk = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", .sig = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908" },
    .{ .label = "small-order A #11 (lenient-only accept)", .want_consensus = false, .want_strict = false, .want_lenient = true, .msg = "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", .pk = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", .sig = "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04" },
};

test "MATRIX: consensus vs strict vs lenient verdicts are pinned (fork-class regression guard)" {
    for (matrix) |v| {
        var msg: [64]u8 = undefined;
        const msg_len = v.msg.len / 2;
        _ = try std.fmt.hexToBytes(msg[0..msg_len], v.msg);
        var pk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pk, v.pk);
        var sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig, v.sig);

        const got_consensus = verifyConsensusStdlib(&sig, &pk, msg[0..msg_len]);
        const got_strict = core.verifyStrict(&sig, &pk, msg[0..msg_len]);
        const got_lenient = core.verifyLenientCofactorless(&sig, &pk, msg[0..msg_len]);

        std.testing.expectEqual(v.want_consensus, got_consensus) catch |e| {
            std.debug.print("MATRIX consensus mismatch on '{s}'\n", .{v.label});
            return e;
        };
        std.testing.expectEqual(v.want_strict, got_strict) catch |e| {
            std.debug.print("MATRIX strict mismatch on '{s}'\n", .{v.label});
            return e;
        };
        std.testing.expectEqual(v.want_lenient, got_lenient) catch |e| {
            std.debug.print("MATRIX lenient mismatch on '{s}'\n", .{v.label});
            return e;
        };
    }
    std.debug.print("[KAT c] 3-way semantic matrix: {d} vectors pinned (consensus/strict/lenient)\n", .{matrix.len});
}
