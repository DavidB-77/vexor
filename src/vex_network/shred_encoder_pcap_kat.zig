//! FD-fixture byte-match KAT for the offline shred encoder (BP staging — strongest gate).
//!
//! Drives `shred_encoder.assembleFecSet` over the real Firedancer pin v0.1002.40103 fixtures and
//! asserts EVERY produced shred is byte-identical to FD's `demo-shreds.pcap`. This is the gate a
//! self-consistency KAT cannot give: it validates against cluster-canonical bytes (partition,
//! per-shred `size`, RS parity, merkle leaf/proof, chained-root threading, resigned last set).
//!
//! Fixture contract (from FD src/disco/shred/test_shredder.c:test_shredder_pcap):
//!   - demo-shreds.bin = 237320-byte entry-batch payload (one block, block_complete=1).
//!   - demo-shreds.key = 64B leader key (seed[0..32] ‖ pubkey[32..64]).
//!   - demo-shreds.pcap = expected shreds, classic LE pcap; each packet = 42B net header + shred.
//!   - shred_version 6051, slot 0, parent_off 0, reference_tick 0.
//!   - 8 FEC sets, each 32 data shreds THEN 32 code shreds, in order.
//!   - chained_merkle_root seed = 0102..0f00 (the parent block's last-FEC root).
//!   - block_complete ⇒ the LAST set is resigned (payload 899, zeroed retransmitter sig at tail).
//!
//! Run: `zig build test-shred-encoder-pcap`. Read-only; reads fixtures from the FD pin on disk.

const std = @import("std");
const enc = @import("shred_encoder.zig");
const layout = @import("shred_layout.zig");
const hdr = @import("shred_header.zig");

// NOTE: this KAT requires a LOCAL Firedancer checkout (not shipped in this
// repo): fixtures from firedancer-io/firedancer tag v0.1002.40103, path
// src/disco/shred/fixtures. Without it the test is skipped/fails to open.
const FIX_DIR = "/home/davidb/firedancer-v0.1002.40103/src/disco/shred/fixtures";

// FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ / _RESIGNED_ (fd_shredder.h): 32 * data_shred_payload_sz.
const CHAINED_PSZ: usize = 30816; // 32 * 963
const RESIGNED_PSZ: usize = 28768; // 32 * 899
const FEC_CNT: usize = 32;
const SHRED_VERSION: u16 = 6051;

fn readFixture(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var pathbuf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&pathbuf, "{s}/{s}", .{ FIX_DIR, name });
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 4 * 1024 * 1024);
}

/// Parse a classic little-endian pcap; return each packet with the 42-byte net header stripped.
fn parsePcapShreds(allocator: std.mem.Allocator, pcap: []const u8) !std.ArrayListUnmanaged([]const u8) {
    var shreds = std.ArrayListUnmanaged([]const u8){};
    errdefer shreds.deinit(allocator);
    std.debug.assert(pcap.len >= 24);
    // magic d4 c3 b2 a1 = classic LE, microsecond.
    std.debug.assert(pcap[0] == 0xd4 and pcap[1] == 0xc3 and pcap[2] == 0xb2 and pcap[3] == 0xa1);
    var p: usize = 24; // skip global header
    while (p + 16 <= pcap.len) {
        const incl_len = std.mem.readInt(u32, pcap[p + 8 ..][0..4], .little);
        p += 16;
        if (p + incl_len > pcap.len) break;
        const packet = pcap[p .. p + incl_len];
        std.debug.assert(packet.len > 42);
        try shreds.append(allocator, packet[42..]); // strip eth(14)+ip(20)+udp(8)
        p += incl_len;
    }
    return shreds;
}

fn firstDiff(a: []const u8, b: []const u8) ?usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) if (a[i] != b[i]) return i;
    if (a.len != b.len) return n;
    return null;
}

test "shred encoder byte-matches FD demo-shreds.pcap (8 FEC sets, 512 shreds)" {
    const allocator = std.testing.allocator;

    const bin = readFixture(allocator, "demo-shreds.bin") catch |e| {
        std.debug.print("[pcap-kat] SKIP: cannot read fixtures ({s}). Is the FD pin present at {s}?\n", .{ @errorName(e), FIX_DIR });
        return error.SkipZigTest;
    };
    defer allocator.free(bin);
    const keybytes = try readFixture(allocator, "demo-shreds.key");
    defer allocator.free(keybytes);
    const pcap = try readFixture(allocator, "demo-shreds.pcap");
    defer allocator.free(pcap);

    try std.testing.expectEqual(@as(usize, 237320), bin.len);
    try std.testing.expectEqual(@as(usize, 64), keybytes.len);
    var sk: [64]u8 = undefined;
    @memcpy(&sk, keybytes[0..64]);

    var expected = try parsePcapShreds(allocator, pcap);
    defer expected.deinit(allocator);
    std.debug.print("[pcap-kat] parsed {d} shreds from pcap (expect 512)\n", .{expected.items.len});
    try std.testing.expectEqual(@as(usize, 512), expected.items.len);

    // chained_merkle_root seed (test_shredder.c:81): 0102030405060708090a0b0c0d0e0f00 twice.
    var chained: [enc.ROOT_SZ]u8 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 } ** 2;

    const block_complete = true;
    var offset: usize = 0;
    var set_idx: usize = 0;
    var matched: usize = 0;

    while (offset < bin.len) : (set_idx += 1) {
        const remaining = bin.len - offset;
        const is_resigned = block_complete and (remaining <= RESIGNED_PSZ);
        const chunk: usize = blk: {
            if (!block_complete) break :blk @min(remaining, CHAINED_PSZ);
            if (is_resigned) break :blk @min(remaining, RESIGNED_PSZ);
            break :blk @min(remaining - RESIGNED_PSZ, CHAINED_PSZ); // save room for the resigned set
        };
        const last_in_batch = (offset + chunk == bin.len);

        const params = enc.FecSetParams{
            .slot = 0,
            .version = SHRED_VERSION,
            .fec_set_idx = @intCast(set_idx * FEC_CNT),
            .data_start_idx = @intCast(set_idx * FEC_CNT),
            .code_start_idx = @intCast(set_idx * FEC_CNT),
            .parent_off = 0,
            .reference_tick = 0,
            // FD flags_for_last: bit6 (DATA_COMPLETE) = last_in_batch; bit7 (SLOT_COMPLETE) =
            // last_in_batch & block_complete. Applied only to the set's last (31st) data shred.
            .data_complete = last_in_batch,
            .slot_complete = last_in_batch and block_complete,
            .is_resigned = is_resigned,
        };

        var set = try enc.assembleFecSet(allocator, params, bin[offset .. offset + chunk], chained, sk);
        defer set.deinit(allocator);
        chained = set.root; // thread to next set

        // Compare 32 data then 32 code against the pcap order for this set.
        for (0..FEC_CNT) |j| {
            const exp = expected.items[set_idx * 64 + j];
            const got = set.data[j];
            if (firstDiff(got, exp)) |d| {
                std.debug.print("[pcap-kat] DATA mismatch set={d} shred={d} at byte {d}: got=0x{x:0>2} exp=0x{x:0>2} (got.len={d} exp.len={d})\n", .{ set_idx, j, d, got[d], exp[d], got.len, exp.len });
                return error.DataShredMismatch;
            }
            matched += 1;
        }
        for (0..FEC_CNT) |j| {
            const exp = expected.items[set_idx * 64 + FEC_CNT + j];
            const got = set.code[j];
            if (firstDiff(got, exp)) |d| {
                std.debug.print("[pcap-kat] CODE mismatch set={d} shred={d} at byte {d}: got=0x{x:0>2} exp=0x{x:0>2} (got.len={d} exp.len={d})\n", .{ set_idx, j, d, got[d], exp[d], got.len, exp.len });
                return error.CodeShredMismatch;
            }
            matched += 1;
        }
        std.debug.print("[pcap-kat] set {d}: chunk={d} resigned={} last={} OK (64/64)\n", .{ set_idx, chunk, is_resigned, last_in_batch });
        offset += chunk;
    }

    try std.testing.expectEqual(@as(usize, 8), set_idx);
    try std.testing.expectEqual(@as(usize, 512), matched);
    std.debug.print("[pcap-kat] PASS — 512/512 shreds byte-identical to FD demo-shreds.pcap\n", .{});
}
