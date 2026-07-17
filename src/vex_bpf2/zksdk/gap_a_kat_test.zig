//! Gap-A consensus KAT for the ZK ElGamal proof port (task #11, 2026-06-19).
//!
//! This is THE deploy gate. It proves the ported Zig verifier (zksdk.*) is byte-faithful to
//! canonical Agave solana-zk-sdk 5.0.1 — NOT merely self-consistent. The fixtures in
//! testdata/agave_zk_vectors.txt are REAL proof bytes emitted by the Agave 5.0.1 off-host PROVER
//! (zk-vector-harness/), each one self-verified Ok by Agave's own verifier. They are
//! non-deterministic one-shot captures (random openings + Fiat-Shamir), so they cannot be
//! regenerated — they are committed (testdata/) as the empirical Sig==Agave oracle.
//!
//!   • accept-real : every genuine Agave proof MUST `fromBytes` + `verify()` Ok under the Zig port.
//!     A pass means the Zig port's transcript labels, deserialization, group math, and final check
//!     all agree with Agave bit-for-bit (a single divergent Merlin label/absorb would fail the
//!     Fiat-Shamir check). This in particular proves the bulletproof generator `table.zig` canonical.
//!   • reject-corrupt : the same proof with its LAST byte flipped (XOR 0xff) MUST be rejected
//!     (fromBytes error OR verify error). Guards against a verifier that accepts anything.
//!
//! Run: `zig test src/vex_bpf2/zksdk/gap_a_kat_test.zig` (module root = zksdk/, so the proof modules'
//! `../root.zig` imports resolve, same as `zig test zksdk.zig`).

const std = @import("std");
const zksdk = @import("zksdk.zig");

const vectors = @embedFile("testdata/agave_zk_vectors.txt");

/// Return the lowercase-hex field (4th token) for the line whose 1st token == `name`.
fn findHex(name: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const n = f.next() orelse continue;
        if (!std.mem.eql(u8, n, name)) continue;
        _ = f.next(); // PROOF_TYPE
        _ = f.next(); // byte_len
        return f.next(); // hex
    }
    return null;
}

// Max wire length across all 12 types is RangeProofU256 = 1064 bytes.
var decode_buf: [1100]u8 = undefined;

fn decode(name: []const u8) ![]const u8 {
    const hex = findHex(name) orelse return error.VectorNotFound;
    return try std.fmt.hexToBytes(&decode_buf, hex);
}

/// A real Agave proof must deserialize AND verify Ok under the Zig port.
fn expectAccept(comptime T: type, name: []const u8) !void {
    const bytes = try decode(name);
    const data = T.fromBytes(bytes) catch |e| {
        std.debug.print("ACCEPT FAIL ({s}): fromBytes -> {any}\n", .{ name, e });
        return error.RealProofRejectedAtDecode;
    };
    data.verify() catch |e| {
        std.debug.print("ACCEPT FAIL ({s}): verify -> {any}\n", .{ name, e });
        return error.RealProofRejectedAtVerify;
    };
}

/// A corrupted proof (last byte flipped) must be rejected somewhere (decode or verify).
fn expectReject(comptime T: type, name: []const u8) !void {
    const bytes = try decode(name);
    const data = T.fromBytes(bytes) catch return; // rejected at decode -> good
    data.verify() catch return; // rejected at verify -> good
    std.debug.print("REJECT FAIL ({s}): corrupt proof was ACCEPTED\n", .{name});
    return error.CorruptProofAccepted;
}

// name in vectors.txt  <->  ported zksdk Data type
const Case = struct { name: []const u8, T: type };
const CASES = [_]Case{
    .{ .name = "ZeroCiphertextProofData", .T = zksdk.ZeroCiphertextData },
    .{ .name = "CiphertextCiphertextEqualityProofData", .T = zksdk.CiphertextCiphertextData },
    .{ .name = "CiphertextCommitmentEqualityProofData", .T = zksdk.CiphertextCommitmentData },
    .{ .name = "PubkeyValidityProofData", .T = zksdk.PubkeyProofData },
    .{ .name = "PercentageWithCapProofData", .T = zksdk.PercentageWithCapData },
    .{ .name = "BatchedRangeProofU64Data", .T = zksdk.RangeProofU64Data },
    .{ .name = "BatchedRangeProofU128Data", .T = zksdk.RangeProofU128Data },
    .{ .name = "BatchedRangeProofU256Data", .T = zksdk.RangeProofU256Data },
    .{ .name = "GroupedCiphertext2HandlesValidityProofData", .T = zksdk.GroupedCiphertext2HandlesData },
    .{ .name = "BatchedGroupedCiphertext2HandlesValidityProofData", .T = zksdk.BatchedGroupedCiphertext2HandlesData },
    .{ .name = "GroupedCiphertext3HandlesValidityProofData", .T = zksdk.GroupedCiphertext3HandlesData },
    .{ .name = "BatchedGroupedCiphertext3HandlesValidityProofData", .T = zksdk.BatchedGroupedCiphertext3HandlesData },
};

test "Gap-A: all 12 real Agave 5.0.1 proofs verify under the Zig port" {
    inline for (CASES) |c| try expectAccept(c.T, c.name);
}

test "Gap-A: all 12 last-byte-corrupted proofs are rejected" {
    var corrupt_name_buf: [128]u8 = undefined;
    inline for (CASES) |c| {
        const cn = try std.fmt.bufPrint(&corrupt_name_buf, "{s}_CORRUPT", .{c.name});
        try expectReject(c.T, cn);
    }
}
