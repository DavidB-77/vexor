//! KAT for the VexLedger append-log blockstore (Phase 1).
//!
//! Each `test` block uses std.testing.allocator (which flags leaks) and a fresh
//! temp dir under .zig-cache/tmp. The ledger path passed to VexLedger.init is a
//! cwd-relative subpath of the temp dir, derived from the TmpDir's realpath.

const std = @import("std");
const vexledger = @import("vex_ledger");
const VexLedger = vexledger.VexLedger;
const SlotMeta = vexledger.SlotMeta;

/// Build an absolute ledger path inside a TmpDir and return it (caller frees).
fn ledgerPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &buf);
    return std.fs.path.join(allocator, &.{ base, name });
}

test "1. round-trip exact bytes" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger1");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const slot: u64 = 100;
    // 5 distinct synthetic payloads of varying length (incl ~1228B + tiny).
    var p_large: [1228]u8 = undefined;
    for (&p_large, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
    const payloads = [_][]const u8{
        "shred-index-0",
        &[_]u8{0xAB},
        "a slightly longer payload for index two .....",
        &p_large,
        &[_]u8{ 0x00, 0xFF, 0x10, 0x20, 0x30 },
    };

    for (payloads, 0..) |p, i| {
        try ledger.putShred(slot, @intCast(i), p);
    }

    // Every shred reads back byte-identical.
    for (payloads, 0..) |p, i| {
        const got = (try ledger.getShred(slot, @intCast(i))).?;
        defer a.free(got);
        try std.testing.expectEqualSlices(u8, p, got);
    }

    // Absent index returns null.
    try std.testing.expect((try ledger.getShred(slot, 99)) == null);
    // Absent slot returns null.
    try std.testing.expect((try ledger.getShred(999, 0)) == null);
}

test "2. FEC-recovery hole-fill (late shred reconstructed from coding)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger2");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const slot: u64 = 42;
    // Arrive out of order with a GAP at index 2 (indices 0,1,3,4).
    const arrivals = [_]u32{ 0, 1, 3, 4 };
    var payload: [16]u8 = undefined;
    for (arrivals) |idx| {
        for (&payload, 0..) |*b, j| b.* = @intCast((idx + j) & 0xff);
        try ledger.putShred(slot, idx, &payload);
    }

    // Index 2 fills in LATE (reconstructed from coding shreds).
    for (&payload, 0..) |*b, j| b.* = @intCast((2 + j) & 0xff);
    try ledger.putShred(slot, 2, &payload);

    // finishSlot with completed_data_indexes = {1, 4}.
    try ledger.finishSlot(slot, .{
        .parent_slot = 41,
        .received = 5,
        .consumed = 5,
        .last_index = 4,
        .connected_flags = vexledger.CONNECTED_FLAG,
        .first_shred_timestamp = 123456,
        .completed_data_indexes = &[_]u32{ 1, 4 },
    });

    // getSlotShredIndices must be complete + sorted {0,1,2,3,4}.
    const indices = try ledger.getSlotShredIndices(a, slot);
    defer a.free(indices);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1, 2, 3, 4 }, indices);

    // All 5 read back exact (incl the late-filled index 2).
    for (0..5) |i| {
        var expect: [16]u8 = undefined;
        for (&expect, 0..) |*b, j| b.* = @intCast((i + j) & 0xff);
        const got = (try ledger.getShred(slot, @intCast(i))).?;
        defer a.free(got);
        try std.testing.expectEqualSlices(u8, &expect, got);
    }
}

test "3. SlotMeta round-trip" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger3");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const slot: u64 = 7;
    const completed = [_]u32{ 1, 4 };
    try ledger.finishSlot(slot, .{
        .parent_slot = 6,
        .received = 5,
        .consumed = 5,
        .last_index = 4,
        .connected_flags = vexledger.CONNECTED_FLAG,
        .first_shred_timestamp = 99887766,
        .completed_data_indexes = &completed,
    });

    const m = (try ledger.meta(a, slot)).?;
    defer a.free(m.completed_data_indexes);
    try std.testing.expectEqual(@as(?u64, 6), m.parent_slot);
    try std.testing.expectEqual(@as(u32, 5), m.received);
    try std.testing.expectEqual(@as(u32, 5), m.consumed);
    try std.testing.expectEqual(@as(?u32, 4), m.last_index);
    try std.testing.expectEqual(vexledger.CONNECTED_FLAG, m.connected_flags);
    try std.testing.expectEqual(@as(u64, 99887766), m.first_shred_timestamp);
    try std.testing.expectEqualSlices(u32, &completed, m.completed_data_indexes);

    // Absent slot meta is null.
    try std.testing.expect((try ledger.meta(a, 123)) == null);

    // None-sentinels round-trip too: parent/last_index = null.
    try ledger.finishSlot(8, .{ .parent_slot = null, .last_index = null });
    const m8 = (try ledger.meta(a, 8)).?;
    defer a.free(m8.completed_data_indexes);
    try std.testing.expect(m8.parent_slot == null);
    try std.testing.expect(m8.last_index == null);
    try std.testing.expectEqual(@as(usize, 0), m8.completed_data_indexes.len);
}

test "4. roots" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger4");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    try ledger.setRoot(10);
    try ledger.setRoot(20);
    try std.testing.expect(ledger.isRoot(10));
    try std.testing.expect(ledger.isRoot(20));
    try std.testing.expect(!ledger.isRoot(30));
}

test "5. crash recovery / index rebuild from log (no WAL)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger5");
    defer a.free(path);

    const completed = [_]u32{ 2, 5 };
    const big_payload = "the quick brown fox jumps over the lazy dog 0123456789";

    // First instance: write shreds + meta + root, then close.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putShred(50, 0, "fifty-zero");
        try ledger.putShred(50, 1, big_payload);
        try ledger.putShred(51, 0, "fifty-one-zero");
        try ledger.finishSlot(50, .{
            .parent_slot = 49,
            .received = 2,
            .consumed = 2,
            .last_index = 1,
            .connected_flags = vexledger.CONNECTED_FLAG,
            .first_shred_timestamp = 555,
            .completed_data_indexes = &completed,
        });
        try ledger.setRoot(50);
    }

    // Second instance on the SAME path: index fully rebuilt from the log.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();

        const g0 = (try ledger.getShred(50, 0)).?;
        defer a.free(g0);
        try std.testing.expectEqualSlices(u8, "fifty-zero", g0);

        const g1 = (try ledger.getShred(50, 1)).?;
        defer a.free(g1);
        try std.testing.expectEqualSlices(u8, big_payload, g1);

        const g2 = (try ledger.getShred(51, 0)).?;
        defer a.free(g2);
        try std.testing.expectEqualSlices(u8, "fifty-one-zero", g2);

        const idx50 = try ledger.getSlotShredIndices(a, 50);
        defer a.free(idx50);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, idx50);

        const m = (try ledger.meta(a, 50)).?;
        defer a.free(m.completed_data_indexes);
        try std.testing.expectEqual(@as(?u64, 49), m.parent_slot);
        try std.testing.expectEqual(@as(?u32, 1), m.last_index);
        try std.testing.expectEqualSlices(u32, &completed, m.completed_data_indexes);

        try std.testing.expect(ledger.isRoot(50));
        try std.testing.expect(!ledger.isRoot(51));

        try std.testing.expectEqual(@as(?u64, 50), ledger.lowestSlot());
        try std.testing.expectEqual(@as(?u64, 51), ledger.highestSlot());
    }
}

test "6. truncated-tail tolerance" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger6");
    defer a.free(path);

    // Write a clean ledger and close.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putShred(70, 0, "intact-0");
        try ledger.putShred(70, 1, "intact-1");
        try ledger.setRoot(70);
    }

    // Append garbage to simulate a torn final write. Two flavors:
    //  (a) a short stub (< 17 bytes) → torn header path.
    //  (b) a full 17-byte header claiming a huge payload that runs past EOF
    //      → torn payload / bogus-len path (must NOT alloc on it).
    {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        // The ACTIVE segment (seq 1) is where appends land in the segmented format.
        var f = try dir.openFile("vexledger-0000000001.seg", .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);
        // Bogus header: kind=0, slot=999, aux=0, len=4_000_000_000 (past EOF).
        var bogus: [17]u8 = undefined;
        bogus[0] = 0;
        std.mem.writeInt(u64, bogus[1..9], 999, .little);
        std.mem.writeInt(u32, bogus[9..13], 0, .little);
        std.mem.writeInt(u32, bogus[13..17], 4_000_000_000, .little);
        try f.writeAll(&bogus);
        // Plus a few trailing stray bytes.
        try f.writeAll(&[_]u8{ 0xDE, 0xAD });
    }

    // Recovery must succeed and return all intact records, ignoring the tail.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();

        const g0 = (try ledger.getShred(70, 0)).?;
        defer a.free(g0);
        try std.testing.expectEqualSlices(u8, "intact-0", g0);
        const g1 = (try ledger.getShred(70, 1)).?;
        defer a.free(g1);
        try std.testing.expectEqualSlices(u8, "intact-1", g1);

        // The bogus record (slot 999) must NOT have been indexed.
        try std.testing.expect((try ledger.getShred(999, 0)) == null);
        try std.testing.expect(ledger.isRoot(70));

        const idx = try ledger.getSlotShredIndices(a, 70);
        defer a.free(idx);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, idx);
    }
}

test "7. append AFTER torn-tail recovery persists correctly" {
    // Regression for the bug where appendRecord used seekFromEnd while indexing
    // the Loc from write_offset: after a torn tail (true-EOF > write_offset), the
    // new shred was written at EOF but indexed into the garbage region → corrupt
    // read, and the on-disk record was placed wrong so a later reopen lost it.
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger7");
    defer a.free(path);

    // Clean ledger with one intact shred, then close.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putShred(80, 0, "intact-pre-crash");
    }

    // Simulate a crash mid-write: append a bogus full header (len past EOF) plus
    // stray bytes — exactly the torn tail recover() must discard.
    {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        var f = try dir.openFile("vexledger-0000000001.seg", .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);
        var bogus: [17]u8 = undefined;
        bogus[0] = 0;
        std.mem.writeInt(u64, bogus[1..9], 999, .little);
        std.mem.writeInt(u32, bogus[9..13], 7, .little);
        std.mem.writeInt(u32, bogus[13..17], 4_000_000_000, .little);
        try f.writeAll(&bogus);
        try f.writeAll(&[_]u8{ 0x11, 0x22, 0x33, 0x44 });
    }

    // Reopen (recovers + truncates the tail), then APPEND a new shred.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putShred(80, 1, "appended-post-crash");

        // Both the pre-crash and the newly-appended shred read back exact.
        const g0 = (try ledger.getShred(80, 0)).?;
        defer a.free(g0);
        try std.testing.expectEqualSlices(u8, "intact-pre-crash", g0);
        const g1 = (try ledger.getShred(80, 1)).?;
        defer a.free(g1);
        try std.testing.expectEqualSlices(u8, "appended-post-crash", g1);
    }

    // Third reopen: the appended shred must have landed at the correct on-disk
    // offset (would be lost/corrupt under the old seekFromEnd+write_offset bug).
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const g1 = (try ledger.getShred(80, 1)).?;
        defer a.free(g1);
        try std.testing.expectEqualSlices(u8, "appended-post-crash", g1);
        const idx = try ledger.getSlotShredIndices(a, 80);
        defer a.free(idx);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, idx);
    }
}

test "8. concurrent writers (RwLock serializes appends)" {
    // Many threads putShred DISJOINT keys at once. The exclusive write lock must
    // serialize each append (seekTo write_offset + writeAll + index put); without
    // it, interleaved appends corrupt write_offset / the on-disk record stream and
    // the read-back below would mismatch. Each thread writes its own slot so keys
    // never collide — the only shared state is write_offset + the maps + the file.
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger8");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const N_THREADS: u32 = 8;
    const PER_THREAD: u32 = 64;

    const Worker = struct {
        fn run(vl: *VexLedger, tid: u32) void {
            var buf: [24]u8 = undefined;
            var i: u32 = 0;
            while (i < PER_THREAD) : (i += 1) {
                // Payload encodes (tid, i) so the read-back can verify exactness.
                for (&buf, 0..) |*b, j| b.* = @intCast((tid *% 31 +% i *% 7 +% @as(u32, @intCast(j))) & 0xff);
                // Each thread owns slot=tid; index=i. Disjoint keys, shared file.
                vl.putShred(@as(u64, tid), i, &buf) catch unreachable;
            }
        }
    };

    var threads: [N_THREADS]std.Thread = undefined;
    for (&threads, 0..) |*t, tid| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ ledger, @as(u32, @intCast(tid)) });
    }
    for (&threads) |t| t.join();

    // Every (tid, i) must be present and byte-exact — proves no append corruption.
    var tid: u32 = 0;
    while (tid < N_THREADS) : (tid += 1) {
        const idxs = try ledger.getSlotShredIndices(a, tid);
        defer a.free(idxs);
        try std.testing.expectEqual(@as(usize, PER_THREAD), idxs.len);
        var i: u32 = 0;
        while (i < PER_THREAD) : (i += 1) {
            var expect: [24]u8 = undefined;
            for (&expect, 0..) |*b, j| b.* = @intCast((tid *% 31 +% i *% 7 +% @as(u32, @intCast(j))) & 0xff);
            const got = (try ledger.getShred(tid, i)).?;
            defer a.free(got);
            try std.testing.expectEqualSlices(u8, &expect, got);
        }
    }
}

/// Write one old-format (single-file) record straight into `f`: the legacy log
/// uses the identical 17-byte header layout, so a legacy `vexledger.log` is just
/// a one-segment log VexLedger reads as seq 0.
fn writeLegacyRecord(f: std.fs.File, kind: u8, slot: u64, aux: u32, payload: []const u8) !void {
    var hdr: [17]u8 = undefined;
    hdr[0] = kind;
    std.mem.writeInt(u64, hdr[1..9], slot, .little);
    std.mem.writeInt(u32, hdr[9..13], aux, .little);
    std.mem.writeInt(u32, hdr[13..17], @intCast(payload.len), .little);
    try f.writeAll(&hdr);
    if (payload.len != 0) try f.writeAll(payload);
}

test "9. segment rolling + cross-segment read (non-active segment served byte-exact)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger9");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    // Tiny threshold so each finishSlot rolls → every slot lands in its own segment.
    ledger.target_segment_bytes = 64;

    // 3 slots, 2 shreds each; payload encodes (slot,index) for an exact read-back.
    var p: [40]u8 = undefined;
    var slot: u64 = 100;
    while (slot < 103) : (slot += 1) {
        var idx: u32 = 0;
        while (idx < 2) : (idx += 1) {
            for (&p, 0..) |*b, j| b.* = @intCast((slot *% 13 +% idx *% 7 +% @as(u64, j)) & 0xff);
            try ledger.putShred(slot, idx, &p);
        }
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 1 });
    }

    // Rolling happened: active segment advanced well past seq 1.
    try std.testing.expect(ledger.active_seq > 1);

    // Slot 100's shreds live in a SEALED (non-active) segment — read across the
    // boundary and assert byte-exact (the gate this KAT exists to prove).
    inline for (.{ 100, 101, 102 }) |s| {
        var idx: u32 = 0;
        while (idx < 2) : (idx += 1) {
            var expect: [40]u8 = undefined;
            for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, s) *% 13 +% idx *% 7 +% @as(u64, j)) & 0xff);
            const got = (try ledger.getShred(s, idx)).?;
            defer a.free(got);
            try std.testing.expectEqualSlices(u8, &expect, got);
        }
    }
}

test "10. recovery across multiple segments" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger10");
    defer a.free(path);

    // First instance: write 4 slots across several segments + a root, then close.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80;
        var slot: u64 = 200;
        while (slot < 204) : (slot += 1) {
            var buf: [50]u8 = undefined;
            for (&buf, 0..) |*b, j| b.* = @intCast((slot *% 17 +% @as(u64, j)) & 0xff);
            try ledger.putShred(slot, 0, &buf);
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
        }
        try ledger.setRoot(203);
    }

    // Second instance: index rebuilt by scanning ALL segments (legacy-absent path).
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        var slot: u64 = 200;
        while (slot < 204) : (slot += 1) {
            var expect: [50]u8 = undefined;
            for (&expect, 0..) |*b, j| b.* = @intCast((slot *% 17 +% @as(u64, j)) & 0xff);
            const got = (try ledger.getShred(slot, 0)).?;
            defer a.free(got);
            try std.testing.expectEqualSlices(u8, &expect, got);
            const m = (try ledger.meta(a, slot)).?;
            defer a.free(m.completed_data_indexes);
            try std.testing.expectEqual(@as(?u64, slot - 1), m.parent_slot);
        }
        try std.testing.expect(ledger.isRoot(203));
        try std.testing.expectEqual(@as(?u64, 200), ledger.lowestSlot());
        try std.testing.expectEqual(@as(?u64, 203), ledger.highestSlot());
    }
}

test "11. legacy vexledger.log read as segment 0 (artifact preserved, new writes go to .seg)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger11");
    defer a.free(path);

    // Hand-craft a legacy single-file log (the pre-segment format).
    try std.fs.cwd().makePath(path);
    var legacy_size: u64 = 0;
    {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        var f = try dir.createFile("vexledger.log", .{ .read = true, .truncate = true });
        defer f.close();
        try writeLegacyRecord(f, 0, 200, 0, "legacy-200-0");
        try writeLegacyRecord(f, 0, 200, 1, "legacy-200-1");
        // meta for slot 200: serialize a minimal fixed-layout record (parent=199,
        // last_index=1, no completed indexes) using the SAME layout the module uses.
        var metabuf: [33]u8 = undefined;
        var o: usize = 0;
        std.mem.writeInt(u64, metabuf[o..][0..8], 199, .little);
        o += 8; // parent
        std.mem.writeInt(u32, metabuf[o..][0..4], 2, .little);
        o += 4; // received
        std.mem.writeInt(u32, metabuf[o..][0..4], 2, .little);
        o += 4; // consumed
        std.mem.writeInt(u32, metabuf[o..][0..4], 1, .little);
        o += 4; // last_index
        metabuf[o] = 1;
        o += 1; // is_connected
        std.mem.writeInt(u64, metabuf[o..][0..8], 0, .little);
        o += 8; // first_shred_timestamp
        std.mem.writeInt(u32, metabuf[o..][0..4], 0, .little);
        o += 4; // num_completed
        try writeLegacyRecord(f, 1, 200, 0, &metabuf);
        try writeLegacyRecord(f, 2, 200, 0, &.{}); // root marker
        legacy_size = try f.getEndPos();
    }

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();

        // Legacy records are visible (read as segment 0).
        const g0 = (try ledger.getShred(200, 0)).?;
        defer a.free(g0);
        try std.testing.expectEqualSlices(u8, "legacy-200-0", g0);
        const g1 = (try ledger.getShred(200, 1)).?;
        defer a.free(g1);
        try std.testing.expectEqualSlices(u8, "legacy-200-1", g1);
        // Legacy SHREDS + ROOT survive; a PRE-V3 legacy META record is best-effort
        // SKIPPED (won't decode as SlotMetaV3) — by design (the bank-exact re-gate
        // uses a fresh Boot-A that writes V3). Shreds/root intact, meta null.
        try std.testing.expect((try ledger.meta(a, 200)) == null);
        try std.testing.expect(ledger.isRoot(200));

        // New writes go to the active .seg (seq 1), NOT the legacy log.
        try std.testing.expectEqual(@as(u32, 1), ledger.active_seq);
        try ledger.putShred(201, 0, "fresh-201-0");
        const g201 = (try ledger.getShred(201, 0)).?;
        defer a.free(g201);
        try std.testing.expectEqualSlices(u8, "fresh-201-0", g201);
    }

    // The legacy artifact must be byte-for-byte UNTOUCHED (opened read-only).
    {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const st = try dir.statFile("vexledger.log");
        try std.testing.expectEqual(legacy_size, st.size);
        // And the active .seg exists separately.
        const seg_st = try dir.statFile("vexledger-0000000001.seg");
        try std.testing.expect(seg_st.size > 0);
    }

    // Reopen: legacy + the new .seg both replay together.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const g0 = (try ledger.getShred(200, 0)).?;
        defer a.free(g0);
        try std.testing.expectEqualSlices(u8, "legacy-200-0", g0);
        const g201 = (try ledger.getShred(201, 0)).?;
        defer a.free(g201);
        try std.testing.expectEqualSlices(u8, "fresh-201-0", g201);
    }
}

test "12. prune: whole-segment eviction below floor (clean, co-located root)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger12");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    ledger.target_segment_bytes = 64; // each finishSlot rolls → one slot per segment.

    // Slots 300..309, each: 2 shreds + root + meta, ALL co-located in that slot's
    // segment (setRoot BEFORE finishSlot so the root record shares the segment).
    var slot: u64 = 300;
    while (slot < 310) : (slot += 1) {
        var idx: u32 = 0;
        while (idx < 2) : (idx += 1) {
            var p: [40]u8 = undefined;
            for (&p, 0..) |*b, j| b.* = @intCast((slot *% 13 +% idx *% 7 +% @as(u64, j)) & 0xff);
            try ledger.putShred(slot, idx, &p);
        }
        try ledger.setRoot(slot);
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 1 });
    }
    const size_before = ledger.byteSize();

    // Keep slots >= 305; evict 300..304.
    const stats = try ledger.purgeSlotsBelow(305);
    try std.testing.expectEqual(@as(u32, 5), stats.segments_unlinked);
    try std.testing.expectEqual(@as(u64, 10), stats.shreds_dropped); // 5 slots × 2
    try std.testing.expectEqual(@as(u64, 5), stats.metas_dropped);
    try std.testing.expectEqual(@as(u64, 5), stats.roots_dropped);
    try std.testing.expectEqual(@as(?u64, 305), stats.lowest_kept);
    try std.testing.expect(stats.bytes_freed > 0);
    try std.testing.expect(ledger.byteSize() < size_before);

    // Evicted slots: fully gone (shred/meta/root). Kept slots: byte-exact, incl
    // slot 305 — the survivor ADJACENT to the evicted neighbor 304.
    var s: u64 = 300;
    while (s < 310) : (s += 1) {
        const kept = s >= 305;
        if (!kept) {
            try std.testing.expect((try ledger.getShred(s, 0)) == null);
            try std.testing.expect((try ledger.meta(a, s)) == null);
            try std.testing.expect(!ledger.isRoot(s));
        } else {
            try std.testing.expect(ledger.isRoot(s));
            var idx: u32 = 0;
            while (idx < 2) : (idx += 1) {
                var expect: [40]u8 = undefined;
                for (&expect, 0..) |*b, j| b.* = @intCast((s *% 13 +% idx *% 7 +% @as(u64, j)) & 0xff);
                const got = (try ledger.getShred(s, idx)).?;
                defer a.free(got);
                try std.testing.expectEqualSlices(u8, &expect, got);
            }
        }
    }
    try std.testing.expectEqual(@as(?u64, 305), ledger.lowestSlot());

    // The evicted segment files must be gone from disk; kept ones present.
    {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        // seq 1..5 held slots 300..304 (evicted); seq 6..10 held 305..309 (kept).
        try std.testing.expect(dir.statFile("vexledger-0000000001.seg") == error.FileNotFound);
        try std.testing.expect(dir.statFile("vexledger-0000000005.seg") == error.FileNotFound);
        _ = try dir.statFile("vexledger-0000000006.seg"); // exists → no error.
    }

    // Recover-after-prune: a fresh open rebuilds ONLY from surviving segments.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        try std.testing.expect((try l2.getShred(304, 0)) == null);
        try std.testing.expect(!l2.isRoot(304));
        try std.testing.expect(l2.isRoot(305));
        const g = (try l2.getShred(305, 1)).?;
        defer a.free(g);
        var expect: [40]u8 = undefined;
        for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, 305) *% 13 +% @as(u64, 1) *% 7 +% @as(u64, j)) & 0xff);
        try std.testing.expectEqualSlices(u8, &expect, g);
        try std.testing.expectEqual(@as(?u64, 305), l2.lowestSlot());
    }
}

test "13. prune: interleaving + cross-segment root + crash-after-unlink consistency" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger13");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    ledger.target_segment_bytes = 64;

    // Interleave: while finishing slot s, also drop a STRAY future shred (s+1,99)
    // into s's segment — so slot s+1 has shreds split across two segments. Then
    // finishSlot(s) rolls. seg(s) ends with max_slot = s+1.
    var slot: u64 = 400;
    while (slot < 406) : (slot += 1) {
        var p: [40]u8 = undefined;
        for (&p, 0..) |*b, j| b.* = @intCast((slot *% 13 +% @as(u64, j)) & 0xff);
        try ledger.putShred(slot, 0, &p);
        if (slot < 405) {
            var pf: [40]u8 = undefined;
            for (&pf, 0..) |*b, j| b.* = @intCast(((slot + 1) *% 13 +% @as(u64, 99) *% 7 +% @as(u64, j)) & 0xff);
            try ledger.putShred(slot + 1, 99, &pf); // stray future shred into seg(slot).
        }
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
    }
    // Root slot 400 LATE → its root record lands in the final (high-seq) segment,
    // which survives the prune. So isRoot(400) must stay true even after 400's
    // DATA is evicted (the root record physically survives on disk).
    try ledger.setRoot(400);

    // Keep slots >= 403. seg(400) max=401, seg(401) max=402 → both < 403 → evicted.
    const stats = try ledger.purgeSlotsBelow(403);
    try std.testing.expect(stats.segments_unlinked >= 2);

    // No read may ever dangle: every (slot,idx) returns bytes or null, never error.
    var s: u64 = 400;
    while (s <= 406) : (s += 1) {
        for ([_]u32{ 0, 99 }) |idx| {
            const r = ledger.getShred(s, idx) catch |e| {
                std.debug.print("DANGLING getShred({d},{d}) err={any}\n", .{ s, idx, e });
                return e;
            };
            if (r) |buf| a.free(buf);
        }
    }

    // slot 402's primary shred is in seg(402) (kept, max=403); its STRAY shred
    // (402,99) was in seg(401) (evicted) → dropped. Survivor + sibling-evicted.
    {
        const g = (try ledger.getShred(402, 0)).?;
        defer a.free(g);
        var expect: [40]u8 = undefined;
        for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, 402) *% 13 +% @as(u64, j)) & 0xff);
        try std.testing.expectEqualSlices(u8, &expect, g);
        try std.testing.expect((try ledger.getShred(402, 99)) == null);
    }
    try std.testing.expect((try ledger.getShred(400, 0)) == null); // 400 data evicted.
    try std.testing.expect(ledger.isRoot(400)); // but its root survives (kept segment).

    // Reopen = the crash-after-unlink test: disk is the source of truth, so the
    // rebuilt in-mem state must EXACTLY match the post-prune queries above.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        try std.testing.expect((try l2.getShred(400, 0)) == null);
        try std.testing.expect(l2.isRoot(400));
        const g = (try l2.getShred(402, 0)).?;
        defer a.free(g);
        var expect: [40]u8 = undefined;
        for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, 402) *% 13 +% @as(u64, j)) & 0xff);
        try std.testing.expectEqualSlices(u8, &expect, g);
        try std.testing.expect((try l2.getShred(402, 99)) == null);
    }
}

test "14. prune: byte-limit FIFO eviction (oldest segments first)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger14");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    ledger.target_segment_bytes = 64;

    // 10 slots, each ~1 segment. Each segment ~ 17+200 (shred) + 17+33 (meta) ≈ 267B.
    var slot: u64 = 500;
    while (slot < 510) : (slot += 1) {
        var p: [200]u8 = undefined;
        for (&p, 0..) |*b, j| b.* = @intCast((slot +% @as(u64, j)) & 0xff);
        try ledger.putShred(slot, 0, &p);
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
    }
    const before = ledger.byteSize();
    try std.testing.expect(before > 0);

    // Bound to half: oldest segments unlink until <= limit.
    const stats = try ledger.pruneToByteLimit(before / 2);
    try std.testing.expect(stats.segments_unlinked > 0);
    try std.testing.expect(ledger.byteSize() <= before / 2);

    // The NEWEST slot (509) must always survive (active/most-recent retained).
    const g = (try ledger.getShred(509, 0)).?;
    defer a.free(g);
    var expect: [200]u8 = undefined;
    for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, 509) +% @as(u64, j)) & 0xff);
    try std.testing.expectEqualSlices(u8, &expect, g);
    // The OLDEST slot (500) must have been evicted first.
    try std.testing.expect((try ledger.getShred(500, 0)) == null);
}

test "15. ordered iterators + per-slot index (dedup re-put, post-prune sync)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger15");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    ledger.target_segment_bytes = 80;

    // Insert slots OUT OF ORDER; re-put a couple shreds (last-wins) to prove the
    // per-slot list stays dup-free.
    const order = [_]u64{ 605, 600, 603, 601, 604, 602 };
    for (order) |slot| {
        try ledger.putShred(slot, 1, "b");
        try ledger.putShred(slot, 0, "a");
        try ledger.putShred(slot, 0, "a2"); // re-put index 0 (overwrite, NOT double-listed).
        try ledger.setRoot(slot);
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 1 });
    }

    // getSlotShredIndices: sorted + dup-free even after the re-put.
    const idx = try ledger.getSlotShredIndices(a, 603);
    defer a.free(idx);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, idx);
    // The re-put won last-wins.
    const g = (try ledger.getShred(603, 0)).?;
    defer a.free(g);
    try std.testing.expectEqualSlices(u8, "a2", g);

    // lowest/highest derive from the per-slot map (not an O(n) scan).
    try std.testing.expectEqual(@as(?u64, 600), ledger.lowestSlot());
    try std.testing.expectEqual(@as(?u64, 605), ledger.highestSlot());

    // slot_meta_iterator(from=602): ascending slots >= 602 with meta.
    {
        const slots = try ledger.slotMetaSlotsFrom(a, 602);
        defer a.free(slots);
        try std.testing.expectEqualSlices(u64, &[_]u64{ 602, 603, 604, 605 }, slots);
    }
    // rooted_slot_iterator(from=0): all roots, ascending.
    {
        const rs = try ledger.rootedSlotsFrom(a, 0);
        defer a.free(rs);
        try std.testing.expectEqualSlices(u64, &[_]u64{ 600, 601, 602, 603, 604, 605 }, rs);
    }

    // After pruning to keep the last 3 slots, the iterators + per-slot lists must
    // reflect ONLY survivors (no stale slots resurrected).
    _ = try ledger.pruneToSlotWindow(3);
    const lk = ledger.lowestSlot().?;
    try std.testing.expect(lk >= 603); // oldest survivors at/after the boundary.
    {
        const slots = try ledger.slotMetaSlotsFrom(a, 0);
        defer a.free(slots);
        for (slots) |s| try std.testing.expect(s >= lk); // no pruned slot in the iterator.
        // And the surviving highest is still 605 with a clean index list.
        const hidx = try ledger.getSlotShredIndices(a, 605);
        defer a.free(hidx);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, hidx);
    }
    // A pruned slot has an empty index list (dropped, not dangling).
    if (lk > 600) {
        const pruned = try ledger.getSlotShredIndices(a, 600);
        defer a.free(pruned);
        try std.testing.expectEqual(@as(usize, 0), pruned.len);
    }
}

test "16. coding shreds (code_shred): round-trip, separate index, prune, recovery" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger16");
    defer a.free(path);

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80;

        // Each slot: 2 data shreds + 2 coding shreds. Data and coding indices are
        // SEPARATE namespaces (both have index 0,1) — must not collide.
        var slot: u64 = 700;
        while (slot < 706) : (slot += 1) {
            try ledger.putShred(slot, 0, "data-0");
            try ledger.putShred(slot, 1, "data-1");
            try ledger.putCodingShred(slot, 0, "code-0");
            try ledger.putCodingShred(slot, 1, "code-1-longer");
            try ledger.putCodingShred(slot, 1, "code-1-longer"); // re-put: dup-free.
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 1 });
        }

        // Data vs coding read back independently, byte-exact, no cross-talk.
        const d0 = (try ledger.getShred(702, 0)).?;
        defer a.free(d0);
        try std.testing.expectEqualSlices(u8, "data-0", d0);
        const c0 = (try ledger.getCodingShred(702, 0)).?;
        defer a.free(c0);
        try std.testing.expectEqualSlices(u8, "code-0", c0);
        const c1 = (try ledger.getCodingShred(702, 1)).?;
        defer a.free(c1);
        try std.testing.expectEqualSlices(u8, "code-1-longer", c1);

        // Separate index lists (the data/coding halves of Agave's `index` CF).
        const dci = try ledger.getCodingShredIndices(a, 702);
        defer a.free(dci);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, dci); // dup-free after re-put.

        // Prune: coding entries evict in lockstep with their segment.
        const stats = try ledger.pruneToSlotWindow(2);
        try std.testing.expect(stats.codes_dropped > 0);
        const lk = ledger.lowestSlot().?;
        if (lk > 700) {
            try std.testing.expect((try ledger.getCodingShred(700, 0)) == null);
            const empty = try ledger.getCodingShredIndices(a, 700);
            defer a.free(empty);
            try std.testing.expectEqual(@as(usize, 0), empty.len);
        }
        // Survivors keep both data + coding byte-exact.
        const hi = ledger.highestSlot().?;
        const sc = (try ledger.getCodingShred(hi, 0)).?;
        defer a.free(sc);
        try std.testing.expectEqualSlices(u8, "code-0", sc);
    }

    // Recovery rebuilds the coding index from segments (KIND_CODE scan).
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const hi = l2.highestSlot().?;
        const c = (try l2.getCodingShred(hi, 1)).?;
        defer a.free(c);
        try std.testing.expectEqualSlices(u8, "code-1-longer", c);
        const ci = try l2.getCodingShredIndices(a, hi);
        defer a.free(ci);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 1 }, ci);
        // Data and coding remain independent after recovery.
        const d = (try l2.getShred(hi, 0)).?;
        defer a.free(d);
        try std.testing.expectEqualSlices(u8, "data-0", d);
    }
}

test "17. getIndexBytes derives byte-exact 8232B Agave index from stored shreds" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger17");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    // data {0,7,8}, coding {1} for slot 900.
    try ledger.putShred(900, 0, "d0");
    try ledger.putShred(900, 7, "d7");
    try ledger.putShred(900, 8, "d8");
    try ledger.putCodingShred(900, 1, "c1");

    const idx = (try ledger.getIndexBytes(a, 900)).?;
    defer a.free(idx);
    try std.testing.expectEqual(@as(usize, 8232), idx.len); // oracle
    try std.testing.expectEqual(@as(u64, 900), std.mem.readInt(u64, idx[0..8], .little));
    // data ShredIndex word0 (offset 16) LSB-first {0,7,8} → 0x81; word1 → 0x01.
    try std.testing.expectEqual(@as(u8, 0x81), idx[16]);
    try std.testing.expectEqual(@as(u8, 0x01), idx[17]);
    // data num_shreds (offset 8+4104) == 3.
    try std.testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, idx[8 + 4104 ..][0..8], .little));
    // coding num_shreds (offset 8+4112+4104) == 1.
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, idx[8 + 4112 + 4104 ..][0..8], .little));

    // No-shred slot → null.
    try std.testing.expect((try ledger.getIndexBytes(a, 999)) == null);
}

test "18. erasure_meta + merkle_root_meta: byte-exact store, prune, recovery" {
    const a = std.testing.allocator;
    const aw = @import("vex_ledger").agave_wire;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger18");
    defer a.free(path);

    var mr: [32]u8 = undefined;
    for (&mr, 0..) |*x, i| x.* = @intCast(i + 1);

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80;

        var slot: u64 = 800;
        while (slot < 806) : (slot += 1) {
            try ledger.putShred(slot, 0, "d"); // keep the slot present for prune windowing.
            try ledger.putErasureMeta(slot, 0, .{ .fec_set_index = 0, .first_coding_index = 32, .first_received_coding_index = 33, .num_data = 32, .num_coding = 32 });
            try ledger.putMerkleRootMeta(slot, 0, .{ .merkle_root = mr, .first_received_shred_index = 0, .first_received_shred_type = aw.SHRED_TYPE_DATA });
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
        }

        // Round-trip exact.
        const em = ledger.getErasureMeta(803, 0).?;
        try std.testing.expectEqual(@as(u64, 32), em.first_coding_index);
        try std.testing.expectEqual(@as(u64, 32), em.num_data);
        const mm = ledger.getMerkleRootMeta(803, 0).?;
        try std.testing.expectEqualSlices(u8, &mr, &mm.merkle_root.?);
        try std.testing.expectEqual(aw.SHRED_TYPE_DATA, mm.first_received_shred_type);
        // Absent → null.
        try std.testing.expect(ledger.getErasureMeta(803, 9) == null);

        // Prune evicts erasure/merkle for old slots in lockstep with their segment.
        _ = try ledger.pruneToSlotWindow(2);
        const lk = ledger.lowestSlot().?;
        if (lk > 800) {
            try std.testing.expect(ledger.getErasureMeta(800, 0) == null);
            try std.testing.expect(ledger.getMerkleRootMeta(800, 0) == null);
        }
        // Survivor keeps both.
        const hi = ledger.highestSlot().?;
        try std.testing.expect(ledger.getErasureMeta(hi, 0) != null);
        try std.testing.expect(ledger.getMerkleRootMeta(hi, 0) != null);
    }

    // Recovery rebuilds erasure_meta + merkle_root_meta from KIND_ERASURE/KIND_MERKLE scan.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const hi = l2.highestSlot().?;
        const em = l2.getErasureMeta(hi, 0).?;
        try std.testing.expectEqual(@as(u64, 33), em.first_received_coding_index);
        const mm = l2.getMerkleRootMeta(hi, 0).?;
        try std.testing.expectEqualSlices(u8, &mr, &mm.merkle_root.?);
    }
}

test "19. SlotMetaV3 byte-exact round-trip through storage + recovery (all new fields)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger19");
    defer a.free(path);

    var pbid: [32]u8 = undefined;
    for (&pbid, 0..) |*x, i| x.* = @intCast(i + 100);
    const flags = vexledger.CONNECTED_FLAG | vexledger.PARENT_CONNECTED_FLAG; // 0x81

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.finishSlot(950, .{
            .parent_slot = 949,
            .received = 64,
            .consumed = 64,
            .last_index = 63,
            .connected_flags = flags,
            .first_shred_timestamp = 777,
            .completed_data_indexes = &[_]u32{ 0, 31, 63 },
            .next_slots = &[_]u64{ 951, 952 },
            .parent_block_id = pbid,
            .replay_fec_set_index = 5,
        });

        const m = (try ledger.meta(a, 950)).?;
        defer a.free(m.completed_data_indexes);
        defer a.free(m.next_slots);
        try std.testing.expectEqual(@as(?u64, 949), m.parent_slot);
        try std.testing.expectEqual(@as(?u32, 63), m.last_index);
        try std.testing.expectEqual(flags, m.connected_flags);
        try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 31, 63 }, m.completed_data_indexes);
        try std.testing.expectEqualSlices(u64, &[_]u64{ 951, 952 }, m.next_slots);
        try std.testing.expectEqualSlices(u8, &pbid, &m.parent_block_id);
        try std.testing.expectEqual(@as(u32, 5), m.replay_fec_set_index);
    }

    // Recovery: V3 meta record decodes byte-exact from the segment scan.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const m = (try l2.meta(a, 950)).?;
        defer a.free(m.completed_data_indexes);
        defer a.free(m.next_slots);
        try std.testing.expectEqual(flags, m.connected_flags);
        try std.testing.expectEqualSlices(u64, &[_]u64{ 951, 952 }, m.next_slots);
        try std.testing.expectEqualSlices(u8, &pbid, &m.parent_block_id);
        try std.testing.expectEqual(@as(u32, 5), m.replay_fec_set_index);
        // None round-trips: a slot with null parent/last_index.
        try l2.finishSlot(960, .{ .parent_slot = null, .last_index = null });
        const m2 = (try l2.meta(a, 960)).?;
        defer a.free(m2.completed_data_indexes);
        defer a.free(m2.next_slots);
        try std.testing.expect(m2.parent_slot == null);
        try std.testing.expect(m2.last_index == null);
    }
}

test "20. blocktime/block_height/rewards slot-keyed records: round-trip, recovery, prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger20");
    defer a.free(path);

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80; // each finishSlot rolls → one slot/segment.

        var slot: u64 = 1000;
        while (slot < 1006) : (slot += 1) {
            try ledger.putShred(slot, 0, "d"); // keep the slot present for prune windowing.
            // blocktime: include a NEGATIVE i64 on one slot to prove sign survival.
            const ts: i64 = if (slot == 1002) -1700000000 else @as(i64, @intCast(slot)) * 1000;
            try ledger.putBlocktime(slot, ts);
            try ledger.putBlockHeight(slot, slot * 7);
            var rbuf: [12]u8 = undefined;
            for (&rbuf, 0..) |*b, j| b.* = @intCast((slot +% @as(u64, j)) & 0xff);
            try ledger.putRewards(slot, &rbuf);
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
        }

        // Round-trip exact (incl negative).
        try std.testing.expectEqual(@as(?i64, -1700000000), ledger.getBlocktime(1002));
        try std.testing.expectEqual(@as(?i64, 1003 * 1000), ledger.getBlocktime(1003));
        try std.testing.expectEqual(@as(?u64, 1003 * 7), ledger.getBlockHeight(1003));
        {
            const r = (try ledger.getRewards(a, 1003)).?;
            defer a.free(r);
            var expect: [12]u8 = undefined;
            for (&expect, 0..) |*b, j| b.* = @intCast((@as(u64, 1003) +% @as(u64, j)) & 0xff);
            try std.testing.expectEqualSlices(u8, &expect, r);
        }
        // Absent → null.
        try std.testing.expect(ledger.getBlocktime(9999) == null);
        try std.testing.expect(ledger.getBlockHeight(9999) == null);
        try std.testing.expect((try ledger.getRewards(a, 9999)) == null);

        // Prune old slots → evicted; survivors intact.
        _ = try ledger.pruneToSlotWindow(2);
        const lk = ledger.lowestSlot().?;
        if (lk > 1000) {
            try std.testing.expect(ledger.getBlocktime(1000) == null);
            try std.testing.expect(ledger.getBlockHeight(1000) == null);
            try std.testing.expect((try ledger.getRewards(a, 1000)) == null);
        }
        const hi = ledger.highestSlot().?;
        try std.testing.expect(ledger.getBlocktime(hi) != null);
        try std.testing.expect(ledger.getBlockHeight(hi) != null);
        const sr = (try ledger.getRewards(a, hi)).?;
        a.free(sr);
    }

    // Recovery: values rebuilt from KIND_BLOCKTIME/KIND_BLOCKHEIGHT/KIND_REWARDS scan.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const hi = l2.highestSlot().?;
        try std.testing.expectEqual(@as(?i64, @as(i64, @intCast(hi)) * 1000), l2.getBlocktime(hi));
        try std.testing.expectEqual(@as(?u64, hi * 7), l2.getBlockHeight(hi));
        const r = (try l2.getRewards(a, hi)).?;
        defer a.free(r);
        var expect: [12]u8 = undefined;
        for (&expect, 0..) |*b, j| b.* = @intCast((hi +% @as(u64, j)) & 0xff);
        try std.testing.expectEqualSlices(u8, &expect, r);
    }
}

test "21. transaction_status + memos + sig_index: round-trip, recovery, G6 lockstep prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger21");
    defer a.free(path);

    // Two distinct synthetic 64-byte signatures (patterned).
    var sigA: [64]u8 = undefined;
    for (&sigA, 0..) |*b, i| b.* = @intCast((i * 3 + 1) & 0xff);
    var sigB: [64]u8 = undefined;
    for (&sigB, 0..) |*b, i| b.* = @intCast((i * 5 + 9) & 0xff);

    const status_a = "protobuf-status-bytes-for-sigA-0123";
    const status_b = &[_]u8{ 0x00, 0xFF, 0x10, 0x20, 0x30, 0x40 };
    const memo_a = "this is a memo for sigA";

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80;

        // sigA at slot 1100, sigB at slot 1105 (different segments after rolls).
        try ledger.putShred(1100, 0, "d");
        // Re-put the SAME (sig, slot) with different bytes first to exercise the
        // overwrite-free path (last-wins; the leak checker proves no double-free).
        try ledger.putTransactionStatus(sigA, 1100, "stale-overwritten");
        try ledger.putTransactionStatus(sigA, 1100, status_a);
        try ledger.putTransactionMemo(sigA, 1100, "stale-memo");
        try ledger.putTransactionMemo(sigA, 1100, memo_a);
        try ledger.finishSlot(1100, .{ .parent_slot = 1099, .last_index = 0 });

        var slot: u64 = 1101;
        while (slot < 1105) : (slot += 1) {
            try ledger.putShred(slot, 0, "d");
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
        }

        try ledger.putShred(1105, 0, "d");
        try ledger.putTransactionStatus(sigB, 1105, status_b);
        try ledger.finishSlot(1105, .{ .parent_slot = 1104, .last_index = 0 });

        // getTransactionStatus returns exact bytes.
        {
            const ga = (try ledger.getTransactionStatus(a, sigA, 1100)).?;
            defer a.free(ga);
            try std.testing.expectEqualSlices(u8, status_a, ga);
            const gb = (try ledger.getTransactionStatus(a, sigB, 1105)).?;
            defer a.free(gb);
            try std.testing.expectEqualSlices(u8, status_b, gb);
        }
        // slotForSignature point lookup.
        try std.testing.expectEqual(@as(?u64, 1100), ledger.slotForSignature(sigA));
        try std.testing.expectEqual(@as(?u64, 1105), ledger.slotForSignature(sigB));
        // Memo round-trip.
        {
            const gm = (try ledger.getTransactionMemo(a, sigA, 1100)).?;
            defer a.free(gm);
            try std.testing.expectEqualSlices(u8, memo_a, gm);
        }
        // Absent → null.
        try std.testing.expect((try ledger.getTransactionStatus(a, sigB, 1100)) == null);
        const sigZ: [64]u8 = [_]u8{0xEE} ** 64;
        try std.testing.expect(ledger.slotForSignature(sigZ) == null);
    }

    // Recovery: all survive (KIND_TX_STATUS/KIND_MEMO scan rebuilds sig_index too).
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const ga = (try l2.getTransactionStatus(a, sigA, 1100)).?;
        defer a.free(ga);
        try std.testing.expectEqualSlices(u8, status_a, ga);
        try std.testing.expectEqual(@as(?u64, 1100), l2.slotForSignature(sigA));
        try std.testing.expectEqual(@as(?u64, 1105), l2.slotForSignature(sigB));
        const gm = (try l2.getTransactionMemo(a, sigA, 1100)).?;
        defer a.free(gm);
        try std.testing.expectEqualSlices(u8, memo_a, gm);

        // Prune keeping the last 2 slots → G6 lockstep drops sigA's old sig-keyed
        // records (slot 1100) + its sig_index entry; sigB (slot 1105) survives.
        const stats = try l2.pruneToSlotWindow(2);
        try std.testing.expect(stats.tx_status_dropped > 0);
        try std.testing.expect(stats.memos_dropped > 0);
        const lk = l2.lowestSlot().?;
        if (lk > 1100) {
            try std.testing.expect((try l2.getTransactionStatus(a, sigA, 1100)) == null);
            try std.testing.expect((try l2.getTransactionMemo(a, sigA, 1100)) == null);
            try std.testing.expect(l2.slotForSignature(sigA) == null); // index entry gone.
        }
        // Survivor intact.
        const gb = (try l2.getTransactionStatus(a, sigB, 1105)).?;
        defer a.free(gb);
        try std.testing.expectEqualSlices(u8, status_b, gb);
        try std.testing.expectEqual(@as(?u64, 1105), l2.slotForSignature(sigB));
    }
}

test "22. address_signatures: round-trip, recovery, prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger22");
    defer a.free(path);

    var pk: [32]u8 = undefined;
    for (&pk, 0..) |*b, i| b.* = @intCast((i * 2 + 7) & 0xff);
    var sig: [64]u8 = undefined;
    for (&sig, 0..) |*b, i| b.* = @intCast((i * 11 + 3) & 0xff);

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 80;

        // One (pk, slot, tx_index, sig) per slot across rolls; alternate writeable.
        var slot: u64 = 1200;
        while (slot < 1206) : (slot += 1) {
            try ledger.putShred(slot, 0, "d");
            const writeable = (slot % 2 == 0);
            try ledger.putAddressSignature(pk, slot, @intCast(slot - 1200), sig, writeable);
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0 });
        }

        // get returns the writeable bool.
        try std.testing.expectEqual(@as(?bool, true), ledger.getAddressSignature(pk, 1200, 0, sig)); // even
        try std.testing.expectEqual(@as(?bool, false), ledger.getAddressSignature(pk, 1201, 1, sig)); // odd
        // Absent (wrong tx_index / wrong sig) → null.
        try std.testing.expect(ledger.getAddressSignature(pk, 1200, 99, sig) == null);
        const sig2: [64]u8 = [_]u8{0xAA} ** 64;
        try std.testing.expect(ledger.getAddressSignature(pk, 1200, 0, sig2) == null);

        // Prune old ones drop in lockstep.
        const stats = try ledger.pruneToSlotWindow(2);
        try std.testing.expect(stats.addr_sigs_dropped > 0);
        const lk = ledger.lowestSlot().?;
        if (lk > 1200) {
            try std.testing.expect(ledger.getAddressSignature(pk, 1200, 0, sig) == null);
        }
        const hi = ledger.highestSlot().?;
        try std.testing.expect(ledger.getAddressSignature(pk, hi, @intCast(hi - 1200), sig) != null);
    }

    // Recovery: survives the KIND_ADDR_SIG scan.
    {
        var l2 = try VexLedger.init(a, path);
        defer l2.deinit();
        const hi = l2.highestSlot().?;
        const expect_writeable = (hi % 2 == 0);
        try std.testing.expectEqual(@as(?bool, expect_writeable), l2.getAddressSignature(pk, hi, @intCast(hi - 1200), sig));
    }
}

test "23. getDataShredsForSlot serves ordered raw data shreds (get_slot_entries source)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger23");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    // Insert out of order; getDataShredsForSlot returns them index-sorted, byte-exact.
    try ledger.putShred(900, 2, "shred-2");
    try ledger.putShred(900, 0, "shred-0");
    try ledger.putShred(900, 1, "shred-1");
    // coding shreds must NOT appear in the DATA read.
    try ledger.putCodingShred(900, 0, "code-0");

    const shreds = try ledger.getDataShredsForSlot(a, 900);
    defer {
        for (shreds) |d| a.free(d.wire);
        a.free(shreds);
    }
    try std.testing.expectEqual(@as(usize, 3), shreds.len);
    try std.testing.expectEqual(@as(u32, 0), shreds[0].index);
    try std.testing.expectEqualSlices(u8, "shred-0", shreds[0].wire);
    try std.testing.expectEqual(@as(u32, 1), shreds[1].index);
    try std.testing.expectEqualSlices(u8, "shred-1", shreds[1].wire);
    try std.testing.expectEqual(@as(u32, 2), shreds[2].index);
    try std.testing.expectEqualSlices(u8, "shred-2", shreds[2].wire);

    // Empty slot → empty slice (no allocation surprises).
    const none = try ledger.getDataShredsForSlot(a, 999);
    defer a.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

// ── Ledger-tile contract KATs (LIVE builds the MPSC ring + tile thread in
// the internal tree post-Phase-2; these gate the VexLedger SIDE of the contract: the
// shared FINISH ring-blob codec + the producer-enqueue→tile-drain→putShred/
// finishSlot sequence + the ring-full DROP path's detectable-gap property). ──

/// A fixed-size ring slot with an INLINE wire buffer — mirrors the tile-spec
/// RingMsg shape exactly (no heap, no shared pointers). The producer memcpy's
/// the shred/FINISH-blob bytes into `buf`; the tile reads `buf[0..len]`.
const MAX_MSG: usize = 1280;
const RingMsg = struct {
    kind: u8, // 0=DATA shred, 1=CODE shred, 2=FINISH(slot)
    slot: u64,
    index: u32,
    len: u32,
    buf: [MAX_MSG]u8 = undefined,
};

/// Producer helper: build a DATA/CODE message by copying `wire` into the inline buf.
fn ringShred(kind: u8, slot: u64, index: u32, wire: []const u8) RingMsg {
    var m = RingMsg{ .kind = kind, .slot = slot, .index = index, .len = @intCast(wire.len) };
    @memcpy(m.buf[0..wire.len], wire);
    return m;
}

/// Producer helper: build a FINISH message by encoding the derived SlotMeta into
/// the inline buf via the shared codec (the exact call LIVE's producer makes).
fn ringFinish(slot: u64, meta: SlotMeta) RingMsg {
    var m = RingMsg{ .kind = 2, .slot = slot, .index = 0, .len = 0 };
    const w = vexledger.FinishBlob.encode(m.buf[0..], meta) catch unreachable;
    m.len = @intCast(w.len);
    return m;
}

/// Consumer helper: drain ONE ring message exactly as the ledger tile would —
/// DATA/CODE → putShred/putCodingShred; FINISH → decode blob → finishSlot.
fn tileDrain(ledger: *VexLedger, a: std.mem.Allocator, m: RingMsg) !void {
    switch (m.kind) {
        0 => try ledger.putShred(m.slot, m.index, m.buf[0..m.len]),
        1 => try ledger.putCodingShred(m.slot, m.index, m.buf[0..m.len]),
        2 => {
            const meta = try vexledger.FinishBlob.decode(a, m.buf[0..m.len]);
            defer a.free(meta.completed_data_indexes); // finishSlot deep-copies
            try ledger.finishSlot(m.slot, meta);
        },
        else => unreachable,
    }
}

test "24. FinishBlob ring-codec round-trips (incl None states + size + read-strictness)" {
    const a = std.testing.allocator;
    const FinishBlob = vexledger.FinishBlob;

    // Rich meta: non-null parent + last_index, parent_block_id set, 3 completed.
    var pbid: [32]u8 = undefined;
    for (&pbid, 0..) |*b, i| b.* = @intCast((i * 3 + 1) & 0xff);
    const completed = [_]u32{ 2, 5, 9 };
    const meta = SlotMeta{
        .parent_slot = 4242,
        .received = 10,
        .consumed = 10,
        .last_index = 9,
        .replay_fec_set_index = 7,
        .connected_flags = 0,
        .first_shred_timestamp = 0x0123_4567_89ab_cdef,
        .completed_data_indexes = &completed,
        .parent_block_id = pbid,
    };

    var buf: [256]u8 = undefined;
    const w = try FinishBlob.encode(&buf, meta);
    try std.testing.expectEqual(FinishBlob.HEADER_LEN + completed.len * 4, w.len);
    try std.testing.expectEqual(FinishBlob.encodedLen(meta), w.len);

    var dec = try FinishBlob.decode(a, w);
    defer a.free(dec.completed_data_indexes);
    try std.testing.expectEqual(@as(?u64, 4242), dec.parent_slot);
    try std.testing.expectEqual(@as(u32, 10), dec.received);
    try std.testing.expectEqual(@as(u32, 10), dec.consumed);
    try std.testing.expectEqual(@as(?u32, 9), dec.last_index);
    try std.testing.expectEqual(@as(u32, 7), dec.replay_fec_set_index);
    try std.testing.expectEqual(@as(u8, 0), dec.connected_flags);
    try std.testing.expectEqual(@as(u64, 0x0123_4567_89ab_cdef), dec.first_shred_timestamp);
    try std.testing.expectEqualSlices(u8, &pbid, &dec.parent_block_id);
    try std.testing.expectEqualSlices(u32, &completed, dec.completed_data_indexes);
    try std.testing.expectEqual(@as(usize, 0), dec.next_slots.len);

    // None states (parent_slot / last_index) round-trip as null (sentinels).
    const none_meta = SlotMeta{ .parent_slot = null, .received = 0, .last_index = null };
    const w2 = try FinishBlob.encode(&buf, none_meta);
    const dec2 = try FinishBlob.decode(a, w2);
    defer a.free(dec2.completed_data_indexes);
    try std.testing.expectEqual(@as(?u64, null), dec2.parent_slot);
    try std.testing.expectEqual(@as(?u32, null), dec2.last_index);
    try std.testing.expectEqual(@as(usize, 0), dec2.completed_data_indexes.len);

    // Oversized blob for a tiny buf → BufferTooSmall (the producer drop+log path).
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, FinishBlob.encode(&tiny, meta));

    // Read-strictness: a num_completed that overruns buf → Truncated, no over-read.
    var corrupt: [FinishBlob.HEADER_LEN]u8 = undefined;
    @memcpy(&corrupt, w[0..FinishBlob.HEADER_LEN]);
    std.mem.writeInt(u32, corrupt[65..69], 1000, .little); // claims 1000 entries, 0 present
    try std.testing.expectError(error.Truncated, FinishBlob.decode(a, &corrupt));
    // A sub-header runt is also rejected.
    try std.testing.expectError(error.Truncated, FinishBlob.decode(a, w[0..10]));
}

test "25. tile-drain reference: producer-enqueue → FIFO drain → putShred/finishSlot" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger24");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    // Derived metas (producer-side; the tile just transports them).
    const c500 = [_]u32{2};
    const meta500 = SlotMeta{ .parent_slot = 499, .received = 3, .consumed = 3, .last_index = 2, .completed_data_indexes = &c500 };
    const c501 = [_]u32{1};
    const meta501 = SlotMeta{ .parent_slot = 500, .received = 2, .consumed = 2, .last_index = 1, .completed_data_indexes = &c501 };

    // FIFO ring contents — two slots INTERLEAVED, each slot's shreds precede its
    // FINISH (the ordering guarantee the MPSC ring must preserve per producer).
    const fifo = [_]RingMsg{
        ringShred(0, 500, 0, "s500-d0"),
        ringShred(0, 501, 0, "s501-d0"),
        ringShred(0, 500, 1, "s500-d1"),
        ringShred(0, 500, 2, "s500-d2"),
        ringFinish(500, meta500),
        ringShred(0, 501, 1, "s501-d1"),
        ringFinish(501, meta501),
    };
    for (fifo) |m| try tileDrain(ledger, a, m);

    // Slot 500: 3 ordered data shreds byte-exact + the finished meta.
    const sh500 = try ledger.getDataShredsForSlot(a, 500);
    defer {
        for (sh500) |d| a.free(d.wire);
        a.free(sh500);
    }
    try std.testing.expectEqual(@as(usize, 3), sh500.len);
    try std.testing.expectEqualSlices(u8, "s500-d1", sh500[1].wire);
    const got500 = (try ledger.meta(a, 500)).?;
    defer a.free(got500.completed_data_indexes);
    defer a.free(got500.next_slots);
    try std.testing.expectEqual(@as(?u64, 499), got500.parent_slot);
    try std.testing.expectEqual(@as(u32, 3), got500.received);
    try std.testing.expectEqual(@as(?u32, 2), got500.last_index);
    try std.testing.expectEqualSlices(u32, &c500, got500.completed_data_indexes);

    // Slot 501 likewise.
    const sh501 = try ledger.getDataShredsForSlot(a, 501);
    defer {
        for (sh501) |d| a.free(d.wire);
        a.free(sh501);
    }
    try std.testing.expectEqual(@as(usize, 2), sh501.len);
    const got501 = (try ledger.meta(a, 501)).?;
    defer a.free(got501.completed_data_indexes);
    defer a.free(got501.next_slots);
    try std.testing.expectEqual(@as(?u64, 500), got501.parent_slot);
    try std.testing.expectEqual(@as(?u32, 1), got501.last_index);
}

test "26. ring-full DROP path: dropped-into slot self-identifies as a gap" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger25");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    var dropped: u64 = 0; // models the producer's drop+log counter on a full ring.

    // Slot 600: the producer DERIVED a 3-shred slot (received=3, last_index=2),
    // but the ring was full when index 1 arrived → that DATA msg dropped. The
    // FINISH still carries the full derived meta (producer saw all 3 shreds).
    try tileDrain(ledger, a, ringShred(0, 600, 0, "s600-d0"));
    dropped += 1; // ringShred(0,600,1,...) would have enqueued here — RING FULL, dropped.
    try tileDrain(ledger, a, ringShred(0, 600, 2, "s600-d2"));
    const c600 = [_]u32{2};
    try tileDrain(ledger, a, ringFinish(600, SlotMeta{ .parent_slot = 599, .received = 3, .consumed = 3, .last_index = 2, .completed_data_indexes = &c600 }));

    // The slot is DETECTABLY incomplete: meta says received=3/last_index=2 but
    // index 1 is absent on disk → a gap an offline-replay driver detects (it
    // aborts a slot that "did NOT complete after feeding all shreds").
    const sh600 = try ledger.getDataShredsForSlot(a, 600);
    defer {
        for (sh600) |d| a.free(d.wire);
        a.free(sh600);
    }
    try std.testing.expectEqual(@as(usize, 2), sh600.len); // only 0 and 2 landed
    try std.testing.expect((try ledger.getShred(600, 1)) == null); // the gap
    const got600 = (try ledger.meta(a, 600)).?;
    defer a.free(got600.completed_data_indexes);
    defer a.free(got600.next_slots);
    try std.testing.expectEqual(@as(u32, 3), got600.received); // meta > stored = gap signal

    // Slot 601: the FINISH msg itself dropped (ring full at completion). The
    // shreds landed but the slot was never finished → no meta = the strongest
    // detectable-incomplete signal (replay never sees a completed slot).
    try tileDrain(ledger, a, ringShred(0, 601, 0, "s601-d0"));
    try tileDrain(ledger, a, ringShred(0, 601, 1, "s601-d1"));
    dropped += 1; // ringFinish(601,...) would have enqueued here — RING FULL, dropped.
    try std.testing.expect((try ledger.meta(a, 601)) == null); // never finished
    const sh601 = try ledger.getDataShredsForSlot(a, 601);
    defer {
        for (sh601) |d| a.free(d.wire);
        a.free(sh601);
    }
    try std.testing.expectEqual(@as(usize, 2), sh601.len); // shreds present, slot incomplete

    try std.testing.expectEqual(@as(u64, 2), dropped); // 2 messages dropped, never wedged
}

// ── P5 #1 per-slot FLIGHT RECORD KATs (bank_hash input decomposition) ────────

test "27. FlightRecord round-trip + recovery byte-exact + wire size (P5 #1)" {
    const a = std.testing.allocator;
    const FlightRecord = vexledger.FlightRecord;

    // Wire-size lock: any layout drift breaks this (32+32+8+32+2048 = 2152).
    try std.testing.expectEqual(@as(usize, 2152), FlightRecord.PAYLOAD_LEN);

    // Direct encode→decode identity with a fully-distinct (non-zero) record.
    var rec1 = FlightRecord{ .signature_count = 1234 };
    for (&rec1.bank_hash, 0..) |*b, i| b.* = @intCast((i * 7 + 1) & 0xff);
    for (&rec1.parent_hash, 0..) |*b, i| b.* = @intCast((i * 3 + 9) & 0xff);
    for (&rec1.poh_hash, 0..) |*b, i| b.* = @intCast((i * 5 + 2) & 0xff);
    for (&rec1.accounts_lt_hash, 0..) |*b, i| b.* = @intCast((i * 13 + 7) & 0xff);
    var wire: [FlightRecord.PAYLOAD_LEN]u8 = undefined;
    rec1.encode(&wire);
    const back = FlightRecord.decode(&wire);
    try std.testing.expectEqualSlices(u8, &rec1.accounts_lt_hash, &back.accounts_lt_hash);
    try std.testing.expectEqual(rec1.signature_count, back.signature_count);
    // sig_count lands at bytes [64..72) LE.
    try std.testing.expectEqual(@as(u64, 1234), std.mem.readInt(u64, wire[64..72], .little));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger27");
    defer a.free(path);

    const rec2 = FlightRecord{ .signature_count = 0, .bank_hash = [_]u8{0xAB} ** 32 };
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putFlightRecord(700, rec1);
        try ledger.putFlightRecord(701, rec2);
        const g = ledger.getFlightRecord(700).?;
        try std.testing.expectEqualSlices(u8, &rec1.bank_hash, &g.bank_hash);
        try std.testing.expectEqualSlices(u8, &rec1.accounts_lt_hash, &g.accounts_lt_hash);
        try std.testing.expectEqual(@as(u64, 1234), g.signature_count);
        try std.testing.expect(ledger.getFlightRecord(999) == null); // absent → null
    }
    // Recovery: maps rebuilt from a full segment scan, byte-identical.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const g1 = ledger.getFlightRecord(700).?;
        try std.testing.expectEqualSlices(u8, &rec1.bank_hash, &g1.bank_hash);
        try std.testing.expectEqualSlices(u8, &rec1.parent_hash, &g1.parent_hash);
        try std.testing.expectEqualSlices(u8, &rec1.poh_hash, &g1.poh_hash);
        try std.testing.expectEqualSlices(u8, &rec1.accounts_lt_hash, &g1.accounts_lt_hash);
        try std.testing.expectEqual(@as(u64, 1234), g1.signature_count);
        const g2 = ledger.getFlightRecord(701).?;
        try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 32), &g2.bank_hash);
        try std.testing.expectEqual(@as(u64, 0), g2.signature_count);
    }
}

test "28. FlightRecord pruned with its backing segment (P5 #1 seq-precise eviction)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger28");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();
    ledger.target_segment_bytes = 80; // a 2152B flight record rolls its own segment

    var slot: u64 = 800;
    while (slot < 806) : (slot += 1) {
        try ledger.putShred(slot, 0, "x");
        var rec = vexledger.FlightRecord{ .signature_count = slot };
        rec.bank_hash[0] = @intCast(slot & 0xff);
        try ledger.putFlightRecord(slot, rec);
        try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
    }
    try ledger.setRoot(805);

    // Evict below 803 → slots 800,801,802 (their whole segments) unlinked.
    const stats = try ledger.purgeSlotsBelow(803);
    try std.testing.expectEqual(@as(u64, 3), stats.flight_dropped);
    try std.testing.expect(ledger.getFlightRecord(800) == null);
    try std.testing.expect(ledger.getFlightRecord(802) == null);
    // Survivors intact + byte-correct.
    try std.testing.expectEqual(@as(u64, 803), ledger.getFlightRecord(803).?.signature_count);
    try std.testing.expectEqual(@as(u64, 805), ledger.getFlightRecord(805).?.signature_count);
}

test "29. bank_hashes CF round-trip + recovery + Agave-wire byte-exact (P5 #1)" {
    const a = std.testing.allocator;
    const agave_wire = vexledger.agave_wire;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger29");
    defer a.free(path);

    var h1: [32]u8 = undefined;
    for (&h1, 0..) |*b, i| b.* = @intCast((i * 11 + 4) & 0xff);
    const h2 = [_]u8{0xCD} ** 32;

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        try ledger.putBankHash(900, h1, true);
        try ledger.putBankHash(901, h2, false);
        const g = ledger.getBankHash(900).?;
        try std.testing.expectEqualSlices(u8, &h1, &g.frozen_hash);
        try std.testing.expectEqual(true, g.is_duplicate_confirmed);
        try std.testing.expect(ledger.getBankHash(999) == null);
        // The stored on-disk VALUE is the canonical 37-byte Agave wincode wire.
        var wire: [agave_wire.FROZEN_HASH_LEN]u8 = undefined;
        agave_wire.encodeFrozenHash(&wire, h1, true);
        try std.testing.expectEqual(@as(usize, 37), wire.len);
    }
    // Recovery: rebuilt from the segment scan, byte-identical + flag preserved.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const g1 = ledger.getBankHash(900).?;
        try std.testing.expectEqualSlices(u8, &h1, &g1.frozen_hash);
        try std.testing.expectEqual(true, g1.is_duplicate_confirmed);
        const g2 = ledger.getBankHash(901).?;
        try std.testing.expectEqualSlices(u8, &h2, &g2.frozen_hash);
        try std.testing.expectEqual(false, g2.is_duplicate_confirmed);
    }
}

// ── getSignaturesForAddress enumeration KATs (RPC-readiness, rc.1 semantics) ──

fn mkSig(seed: u8) [64]u8 {
    return [_]u8{seed} ** 64;
}

test "30. getSignaturesForAddress ordering + before/until pagination + limit + highest_slot" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger30");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const pk = [_]u8{0x11} ** 32;
    const A = mkSig(0xA0); // slot 10, tx 0
    const B = mkSig(0xB0); // slot 10, tx 1
    const C = mkSig(0xC0); // slot 12, tx 0
    const D = mkSig(0xD0); // slot 11, tx 5
    // Insert out of order; a different pubkey's sig must not leak in.
    try ledger.putAddressSignature(pk, 10, 0, A, true);
    try ledger.putAddressSignature(pk, 12, 0, C, true);
    try ledger.putAddressSignature(pk, 10, 1, B, false);
    try ledger.putAddressSignature(pk, 11, 5, D, true);
    try ledger.putAddressSignature([_]u8{0x22} ** 32, 13, 0, mkSig(0xEE), true);

    // Newest-first = (slot DESC, tx_index DESC) → [C(12,0), D(11,5), B(10,1), A(10,0)].
    const all = try ledger.getSignaturesForAddress(a, pk, null, null, 1000, null);
    defer a.free(all);
    try std.testing.expectEqual(@as(usize, 4), all.len);
    try std.testing.expectEqualSlices(u8, &C, &all[0].signature);
    try std.testing.expectEqual(@as(u64, 12), all[0].slot);
    try std.testing.expectEqualSlices(u8, &D, &all[1].signature);
    try std.testing.expectEqual(@as(u32, 5), all[1].tx_index);
    try std.testing.expectEqualSlices(u8, &B, &all[2].signature);
    try std.testing.expectEqualSlices(u8, &A, &all[3].signature);

    // limit caps the count (still newest-first).
    const lim2 = try ledger.getSignaturesForAddress(a, pk, null, null, 2, null);
    defer a.free(lim2);
    try std.testing.expectEqual(@as(usize, 2), lim2.len);
    try std.testing.expectEqualSlices(u8, &C, &lim2[0].signature);
    try std.testing.expectEqualSlices(u8, &D, &lim2[1].signature);

    // before=C EXCLUSIVE → start strictly after C → [D, B, A].
    const bef = try ledger.getSignaturesForAddress(a, pk, C, null, 1000, null);
    defer a.free(bef);
    try std.testing.expectEqual(@as(usize, 3), bef.len);
    try std.testing.expectEqualSlices(u8, &D, &bef[0].signature);
    try std.testing.expectEqualSlices(u8, &A, &bef[2].signature);

    // until=B EXCLUSIVE → stop strictly before B → [C, D].
    const unt = try ledger.getSignaturesForAddress(a, pk, null, B, 1000, null);
    defer a.free(unt);
    try std.testing.expectEqual(@as(usize, 2), unt.len);
    try std.testing.expectEqualSlices(u8, &C, &unt[0].signature);
    try std.testing.expectEqualSlices(u8, &D, &unt[1].signature);

    // before=C + until=B → just [D].
    const win = try ledger.getSignaturesForAddress(a, pk, C, B, 1000, null);
    defer a.free(win);
    try std.testing.expectEqual(@as(usize, 1), win.len);
    try std.testing.expectEqualSlices(u8, &D, &win[0].signature);

    // highest_slot=11 → skip slot>11 (C dropped) → [D, B, A].
    const hs = try ledger.getSignaturesForAddress(a, pk, null, null, 1000, 11);
    defer a.free(hs);
    try std.testing.expectEqual(@as(usize, 3), hs.len);
    try std.testing.expectEqualSlices(u8, &D, &hs[0].signature);

    // before not found → empty; until not found → ignored (full list).
    const bnf = try ledger.getSignaturesForAddress(a, pk, mkSig(0x77), null, 1000, null);
    defer a.free(bnf);
    try std.testing.expectEqual(@as(usize, 0), bnf.len);
    const unf = try ledger.getSignaturesForAddress(a, pk, null, mkSig(0x77), 1000, null);
    defer a.free(unf);
    try std.testing.expectEqual(@as(usize, 4), unf.len);

    // unknown pubkey → empty (freeable).
    const none = try ledger.getSignaturesForAddress(a, [_]u8{0x99} ** 32, null, null, 1000, null);
    defer a.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "31. getSignaturesForAddress survives recovery + seq-precise prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger31");
    defer a.free(path);

    const pk = [_]u8{0x33} ** 32;
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 60; // roll each slot into its own segment
        var slot: u64 = 700;
        while (slot < 705) : (slot += 1) {
            try ledger.putShred(slot, 0, "x");
            try ledger.putAddressSignature(pk, slot, 0, mkSig(@intCast(slot & 0xff)), true);
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
        }
        try ledger.setRoot(704);
    }
    // Recovery: the enumeration index is rebuilt from the segment scan.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const before = try ledger.getSignaturesForAddress(a, pk, null, null, 1000, null);
        defer a.free(before);
        try std.testing.expectEqual(@as(usize, 5), before.len);
        try std.testing.expectEqual(@as(u64, 704), before[0].slot); // newest-first

        // Prune below 702 → slots 700,701 evicted from BOTH addr_sigs + the index.
        const stats = try ledger.purgeSlotsBelow(702);
        try std.testing.expectEqual(@as(u64, 2), stats.addr_sigs_dropped);
        const after = try ledger.getSignaturesForAddress(a, pk, null, null, 1000, null);
        defer a.free(after);
        try std.testing.expectEqual(@as(usize, 3), after.len); // 702,703,704
        try std.testing.expectEqual(@as(u64, 702), after[after.len - 1].slot); // oldest kept
    }
}

test "32. getSlotSignatures block-order + dedup + no cross-slot leak + empty" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger32");
    defer a.free(path);

    var ledger = try VexLedger.init(a, path);
    defer ledger.deinit();

    const sA = mkSig(0xA0); // slot 50, tx 0
    const sB = mkSig(0xB0); // slot 50, tx 1
    const sC = mkSig(0xC0); // slot 50, tx 2
    // Insert out of execution order; a different slot's sig must not leak in.
    try ledger.putSlotSignature(50, 2, sC);
    try ledger.putSlotSignature(50, 0, sA);
    try ledger.putSlotSignature(50, 1, sB);
    try ledger.putSlotSignature(51, 0, mkSig(0x5A));

    // Block order = tx_index ASCENDING → [A(0), B(1), C(2)].
    const got = try ledger.getSlotSignatures(a, 50);
    defer a.free(got);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqual(@as(u32, 0), got[0].tx_index);
    try std.testing.expectEqualSlices(u8, &sA, &got[0].signature);
    try std.testing.expectEqual(@as(u32, 1), got[1].tx_index);
    try std.testing.expectEqualSlices(u8, &sB, &got[1].signature);
    try std.testing.expectEqual(@as(u32, 2), got[2].tx_index);
    try std.testing.expectEqualSlices(u8, &sC, &got[2].signature);

    // Dedup: re-put (50,0) with a DIFFERENT sig → no new row; first-write-wins.
    try ledger.putSlotSignature(50, 0, mkSig(0x99));
    const got2 = try ledger.getSlotSignatures(a, 50);
    defer a.free(got2);
    try std.testing.expectEqual(@as(usize, 3), got2.len);
    try std.testing.expectEqualSlices(u8, &sA, &got2[0].signature); // still the original

    // Unknown slot → empty (freeable).
    const none = try ledger.getSlotSignatures(a, 999);
    defer a.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "33. getSlotSignatures survives recovery + seq-precise prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger33");
    defer a.free(path);

    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 60; // roll each slot into its own segment
        var slot: u64 = 600;
        while (slot < 605) : (slot += 1) {
            try ledger.putShred(slot, 0, "x");
            try ledger.putSlotSignature(slot, 0, mkSig(@intCast(slot & 0xff)));
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
        }
        try ledger.setRoot(604);
    }
    // Recovery: the slot→sig index is rebuilt from the segment scan.
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const s603 = try ledger.getSlotSignatures(a, 603);
        defer a.free(s603);
        try std.testing.expectEqual(@as(usize, 1), s603.len);
        const want603 = mkSig(@as(u8, 603 & 0xff));
        try std.testing.expectEqualSlices(u8, &want603, &s603[0].signature);

        // Prune below 602 → slots 600,601 evicted from BOTH slot_sigs + the index.
        const stats = try ledger.purgeSlotsBelow(602);
        try std.testing.expectEqual(@as(u64, 2), stats.slot_sigs_dropped);
        const gone = try ledger.getSlotSignatures(a, 600);
        defer a.free(gone);
        try std.testing.expectEqual(@as(usize, 0), gone.len);
        const kept = try ledger.getSlotSignatures(a, 604);
        defer a.free(kept);
        try std.testing.expectEqual(@as(usize, 1), kept.len);
    }
}

test "34. tx_wire round-trip + last-wins + recovery + seq-precise prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger34");
    defer a.free(path);

    const sX = mkSig(0x71);
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 90; // roll segments so prune can evict per-slot

        try ledger.putTransactionWire(sX, 900, "hello-wire");
        // last-wins per (sig, slot).
        try ledger.putTransactionWire(sX, 900, "second-wire-longer");
        const w = (try ledger.getTransactionWire(a, sX, 900)).?;
        defer a.free(w);
        try std.testing.expectEqualStrings("second-wire-longer", w);
        // absent (sig,slot) → null.
        try std.testing.expect((try ledger.getTransactionWire(a, mkSig(0x99), 900)) == null);

        // populate a few more slots so prune has a boundary.
        var slot: u64 = 901;
        while (slot < 905) : (slot += 1) {
            try ledger.putShred(slot, 0, "x");
            try ledger.putTransactionWire(mkSig(@intCast(slot & 0xff)), slot, "w");
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
        }
        try ledger.setRoot(904);
    }
    // Recovery: tx_wire rebuilt from the segment scan (last-wins preserved).
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        const w = (try ledger.getTransactionWire(a, sX, 900)).?;
        defer a.free(w);
        try std.testing.expectEqualStrings("second-wire-longer", w);

        // Prune below 903 → slots 900,901,902 evicted from tx_wire.
        const stats = try ledger.purgeSlotsBelow(903);
        try std.testing.expect(stats.tx_wire_dropped >= 3); // sX@900 (2 records→1 entry) + 901 + 902
        try std.testing.expect((try ledger.getTransactionWire(a, sX, 900)) == null);
        const survivor = (try ledger.getTransactionWire(a, mkSig(904 & 0xff), 904)).?;
        defer a.free(survivor);
        try std.testing.expectEqualStrings("w", survivor);
    }
}

test "35. blockhash round-trip + last-wins + recovery + seq-precise prune" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try ledgerPath(a, &tmp, "ledger35");
    defer a.free(path);

    const h1 = [_]u8{0xAB} ** 32;
    const h2 = [_]u8{0xCD} ** 32;
    {
        var ledger = try VexLedger.init(a, path);
        defer ledger.deinit();
        ledger.target_segment_bytes = 70; // roll segments for per-slot eviction
        try ledger.putBlockhash(700, h1);
        try ledger.putBlockhash(700, h2); // last-wins
        try std.testing.expectEqualSlices(u8, &h2, &ledger.getBlockhash(700).?);
        try std.testing.expect(ledger.getBlockhash(999) == null);
        var slot: u64 = 701;
        while (slot < 705) : (slot += 1) {
            try ledger.putShred(slot, 0, "x");
            try ledger.putBlockhash(slot, [_]u8{@intCast(slot & 0xff)} ** 32);
            try ledger.finishSlot(slot, .{ .parent_slot = slot - 1, .last_index = 0, .completed_data_indexes = &[_]u32{0} });
        }
        try ledger.setRoot(704);
    }
    {
        var ledger = try VexLedger.init(a, path); // recovery rebuilds blockhash map
        defer ledger.deinit();
        try std.testing.expectEqualSlices(u8, &h2, &ledger.getBlockhash(700).?); // last-wins survived
        const stats = try ledger.purgeSlotsBelow(703);
        try std.testing.expect(stats.blockhash_dropped >= 3); // 700,701,702
        try std.testing.expect(ledger.getBlockhash(700) == null);
        try std.testing.expectEqualSlices(u8, &([_]u8{704 & 0xff} ** 32), &ledger.getBlockhash(704).?);
    }
}
