//! KAT: DuplicateShred (CRDS type 9) Tier-1 — wire layout, chunking, sign/verify.
//!
//! Canonical reference: Agave 4.1.0-rc.1 (git 5efbb99)
//!   gossip/src/crds_data.rs:59  DuplicateShred(DuplicateShredIndex u16, DuplicateShred)
//!   gossip/src/duplicate_shred.rs:26-42, 236-281  struct + from_shred + chunking
//!   ledger/src/blockstore_meta.rs:355  DuplicateSlotProof { shred1, shred2 }
//!
//! What this proves (and ONLY this):
//!   (a) CrdsData.DuplicateShred wire layout is byte-exact: tag@0=9 (u32 LE),
//!       index@4 (u16 LE), from@6..38, _unused first byte == 0,
//!       _unused_shred_type == 90, chunk_len present.
//!   (b) DuplicateSlotProof [len1][raw1][len2][raw2] round-trips.
//!   (c) Chunking: a proof spanning >1 chunk yields correct num_chunks /
//!       chunk_index and reassembles to the original.
//!   (d) sign -> verify round-trip of the CrdsValue against self_pubkey.
//!
//! What it does NOT prove: live detection firing on a real equivocation, or
//! cross-validator acceptance of the pushed proof.

const std = @import("std");
const dupshred = @import("duplicate_shred");
const crds = dupshred.crds_mod; // same crds instance dupshred uses
const crypto = @import("vex_crypto");

// ── (a) byte-exact wire layout of CrdsData.DuplicateShred ────────────────────
test "(a) CrdsData.DuplicateShred wire layout byte-exact" {
    const chunk_bytes = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const from: [32]u8 = [_]u8{0x11} ** 32;
    const ds = crds.DuplicateShred{
        .index = 0x0102, // u16 = 0x0102 -> LE bytes 02 01
        .from = from,
        .wallclock = 0x1122334455667788,
        .slot = 0x00000000DEADBEEF,
        ._unused = 0,
        ._unused_shred_type = crds.DuplicateShred.UNUSED_SHRED_TYPE_CODE,
        .num_chunks = 3,
        .chunk_index = 1,
        .chunk = &chunk_bytes,
    };
    const data = crds.CrdsData{ .DuplicateShred = ds };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try data.serialize(fbs.writer());
    const wire = fbs.getWritten();

    // tag@0 = 9 (u32 LE)
    try std.testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, wire[0..4], .little));
    // index@4 = 0x0102 (u16 LE)
    try std.testing.expectEqual(@as(u16, 0x0102), std.mem.readInt(u16, wire[4..6], .little));
    // from@6..38
    try std.testing.expectEqualSlices(u8, &from, wire[6..38]);
    // wallclock@38..46
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), std.mem.readInt(u64, wire[38..46], .little));
    // slot@46..54
    try std.testing.expectEqual(@as(u64, 0x00000000DEADBEEF), std.mem.readInt(u64, wire[46..54], .little));
    // _unused@54..58 == 0 (first byte and all four)
    try std.testing.expectEqual(@as(u8, 0), wire[54]);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, wire[54..58], .little));
    // _unused_shred_type@58 == 90 (ShredType::Code)
    try std.testing.expectEqual(@as(u8, 90), wire[58]);
    // num_chunks@59 == 3
    try std.testing.expectEqual(@as(u8, 3), wire[59]);
    // chunk_index@60 == 1
    try std.testing.expectEqual(@as(u8, 1), wire[60]);
    // chunk_len@61..69 (u64 LE) == 4
    try std.testing.expectEqual(@as(u64, 4), std.mem.readInt(u64, wire[61..69], .little));
    // chunk bytes@69..73
    try std.testing.expectEqualSlices(u8, &chunk_bytes, wire[69..73]);
    // total = 4(tag)+2(index)+32+8+8+4+1+1+1+8+4 = 73
    try std.testing.expectEqual(@as(usize, 73), wire.len);

    // Fixed header size assertion: everything before chunk_len (the 63-byte
    // DUPLICATE_SHRED_HEADER_SIZE accounting maps to the per-chunk Agave header,
    // here we assert our on-wire fixed prefix up to and including chunk_len is
    // tag(4)+index(2)+57 fixed body + 8 chunk_len = 71 bytes before chunk data).
    try std.testing.expectEqual(@as(usize, 69), wire.len - chunk_bytes.len);

    // Cross-check the gossip getCrdsValueSize tag-9 WALK formula against the
    // actual serialized CrdsValue. The walk is: sig(64) + tag(4) + [index(2)
    // + from(32) + wallclock(8) + slot(8) + _unused(4) + _unused_shred_type(1)
    // + num_chunks(1) + chunk_index(1)] + chunk_len(8) + chunk bytes.
    // Build the FULL CrdsValue (sig + data) and confirm the formula matches.
    const cv = crds.CrdsValue{ .signature = [_]u8{0} ** 64, .data = data };
    var cvbuf: [512]u8 = undefined;
    var cvfbs = std.io.fixedBufferStream(&cvbuf);
    try cv.serialize(cvfbs.writer());
    const cv_wire = cvfbs.getWritten();
    const walk_size: usize = 64 + 4 + (2 + 32 + 8 + 8 + 4 + 1 + 1 + 1) + 8 + chunk_bytes.len;
    try std.testing.expectEqual(walk_size, cv_wire.len);
}

// ── (b) DuplicateSlotProof [len1][raw1][len2][raw2] round-trip ───────────────
test "(b) DuplicateSlotProof round-trips" {
    const a = std.testing.allocator;
    // Deterministic synthetic shreds: same first bytes (id), differ in body.
    var s1: [120]u8 = undefined;
    var s2: [140]u8 = undefined;
    for (&s1, 0..) |*x, i| x.* = @intCast(i & 0xff);
    for (&s2, 0..) |*x, i| x.* = @intCast(i & 0xff);
    @memcpy(s2[0..64], s1[0..64]); // share the first 64 bytes (signature/id region)
    s2[80] = 0xFF; // differ in body

    const proof = try dupshred.serializeDuplicateSlotProof(a, &s1, &s2);
    defer a.free(proof);

    // header bytes: len1 then raw1 then len2 then raw2
    try std.testing.expectEqual(@as(u64, 120), std.mem.readInt(u64, proof[0..8], .little));
    const parsed = try dupshred.parseDuplicateSlotProof(proof);
    try std.testing.expectEqualSlices(u8, &s1, parsed.shred1);
    try std.testing.expectEqualSlices(u8, &s2, parsed.shred2);
    try std.testing.expectEqual(@as(usize, 8 + 120 + 8 + 140), proof.len);
}

// ── (c) chunking: >1 chunk, correct num_chunks/chunk_index, reassembles ──────
test "(c) chunking spans multiple chunks and reassembles" {
    const a = std.testing.allocator;
    // Make two large shreds so the proof exceeds one 1054-byte chunk.
    // proof len = 8 + 1200 + 8 + 1200 = 2416 -> ceil(2416/1054) = 3 chunks.
    var s1: [1200]u8 = undefined;
    var s2: [1200]u8 = undefined;
    for (&s1, 0..) |*x, i| x.* = @intCast(i & 0xff);
    for (&s2, 0..) |*x, i| x.* = @intCast((i +% 1) & 0xff);
    @memcpy(s2[0..64], s1[0..64]);

    const proof_expected = try dupshred.serializeDuplicateSlotProof(a, &s1, &s2);
    defer a.free(proof_expected);

    const secret = testSecretKey();
    const self_pubkey = secret[32..64].*;

    const chunks = try dupshred.buildSignedProofChunks(
        a,
        &s1,
        &s2,
        secret,
        self_pubkey,
        12345, // wallclock
        777_000, // slot
        0, // index_offset
    );
    defer {
        for (chunks) |*c| c.deinit();
        a.free(chunks);
    }

    const expected_num_chunks: u8 = @intCast((proof_expected.len + dupshred.DUPLICATE_SHRED_CHUNK_SIZE - 1) / dupshred.DUPLICATE_SHRED_CHUNK_SIZE);
    try std.testing.expect(expected_num_chunks > 1);
    try std.testing.expectEqual(@as(usize, expected_num_chunks), chunks.len);

    // chunk_index is 0-based ascending, num_chunks consistent, indices rotate.
    var reassembled = std.ArrayListUnmanaged(u8){};
    defer reassembled.deinit(a);
    for (chunks, 0..) |*c, i| {
        const ds = c.value.data.DuplicateShred;
        try std.testing.expectEqual(@as(u8, expected_num_chunks), ds.num_chunks);
        try std.testing.expectEqual(@as(u8, @intCast(i)), ds.chunk_index);
        try std.testing.expectEqual(@as(u16, @intCast(i % dupshred.MAX_DUPLICATE_SHREDS)), ds.index);
        try std.testing.expectEqual(@as(u64, 777_000), ds.slot);
        try std.testing.expectEqual(self_pubkey, ds.from);
        try reassembled.appendSlice(a, c.chunk);
    }
    // Reassembled chunk bytes == original serialized proof, which parses back.
    try std.testing.expectEqualSlices(u8, proof_expected, reassembled.items);
    const reparsed = try dupshred.parseDuplicateSlotProof(reassembled.items);
    try std.testing.expectEqualSlices(u8, &s1, reparsed.shred1);
    try std.testing.expectEqualSlices(u8, &s2, reparsed.shred2);
}

// ── (d) sign -> verify round-trip of the CrdsValue ───────────────────────────
test "(d) CrdsValue sign->verify round-trips against self_pubkey" {
    const a = std.testing.allocator;
    var s1: [200]u8 = undefined;
    var s2: [200]u8 = undefined;
    for (&s1, 0..) |*x, i| x.* = @intCast(i & 0xff);
    for (&s2, 0..) |*x, i| x.* = @intCast(i & 0xff);
    @memcpy(s2[0..64], s1[0..64]);
    s2[100] = 0x42; // differ in body

    const secret = testSecretKey();
    const self_pubkey = secret[32..64].*;

    const chunks = try dupshred.buildSignedProofChunks(
        a,
        &s1,
        &s2,
        secret,
        self_pubkey,
        999, // wallclock
        424242, // slot
        0,
    );
    defer {
        for (chunks) |*c| c.deinit();
        a.free(chunks);
    }
    try std.testing.expect(chunks.len >= 1);

    for (chunks) |*c| {
        // CrdsValue.verify() pulls the pubkey from the data (ds.from) and checks
        // the signature over bincode(CrdsData). Must pass for our self_pubkey.
        try std.testing.expect(c.value.verify());
        // pubkey() returns &ds.from == self_pubkey.
        try std.testing.expectEqualSlices(u8, &self_pubkey, c.value.data.pubkey().?);
        // A corrupted signature must FAIL (negative control).
        var bad = c.value;
        bad.signature[0] ^= 0xFF;
        try std.testing.expect(!bad.verify());
    }
}

// Identical payloads are not a conflict.
test "(e) identical payloads rejected" {
    const a = std.testing.allocator;
    const s = [_]u8{0x7} ** 100;
    const secret = testSecretKey();
    try std.testing.expectError(
        error.IdenticalPayloads,
        dupshred.buildSignedProofChunks(a, &s, &s, secret, secret[32..64].*, 1, 2, 0),
    );
}

/// Deterministic Solana-format secret key [seed(32)][pubkey(32)] derived from a
/// fixed seed. Uses the same Ed25519 keygen as the validator so verify() lines
/// up with the public half.
fn testSecretKey() [64]u8 {
    const seed = [_]u8{0x2A} ** 32;
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    var sk: [64]u8 = undefined;
    @memcpy(sk[0..32], &seed);
    @memcpy(sk[32..64], &kp.public_key.bytes);
    return sk;
}
