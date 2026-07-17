//! KAT: snapshot-load manifest-length provenance (carrier @414371294, 2026-06-10)
//!
//! PROVEN ROOT: PDA 2FC547gLsf91DH83Ajs8xU32V18gNz5NEvdkSSptZ7t7 (Jito
//! ClusterHistory, 131,352 B data) lives as the LAST entry of FULL-archive
//! appendvec 414364417.1455839 (file 131,624 B). The FULL manifest
//! (snapshots/414364674) records len 131,624; the INCREMENTAL manifest
//! (snapshots/414370616) records 131,488 (post-shrink layout; the file itself
//! is NOT re-shipped by the incremental). Pre-fix, findManifestSlot picked the
//! highest (incremental) manifest unconditionally and its 131,488 was applied
//! to the pre-shrink 131,624-B file → mmapAndIndex hit
//! data_end 131,624 > 131,488 and silently broke → the PDA never indexed
//! ("0 errors") → empty-stub served to the VM → Anchor 3007 where the cluster
//! succeeds (790,545 CU) → write dropped → lt diverges @414371294.
//!
//! This KAT synthesizes the exact dual-manifest shape (dead 136-B entry0 +
//! live tail entry whose data ends exactly at EOF) and asserts:
//!   1. FAIL-before/PASS-after: parsing with the WRONG (incremental) length
//!      still indexes the tail account (loud tail-scan recovery) — pre-fix the
//!      account was silently dropped.
//!   2. mergeFileSzMapsByProvenance keys lengths by archive provenance
//!      (full manifest for slot ≤ full_slot, incremental above), mirroring
//!      Agave's AccountsDbFields::get_storage_lengths_for_snapshot_slots.
//!   3. With the correct (full-manifest) length the tail account is indexed
//!      with ZERO mismatch counters.
//!   4. Healthy zero-padding beyond the manifest length stays silent.

const std = @import("std");
const core = @import("core");
const parallel_snapshot = @import("parallel_snapshot.zig");
const snapshot_manifest = @import("snapshot_manifest.zig");
const accounts = @import("accounts.zig");

const FULL_SLOT: u64 = 414364674;
const FILE_SLOT: u64 = 414364417;
const FILE_ID: u64 = 1455839;

// Synthetic stand-ins for the real geometry (data scaled 131,352 → 1,000).
const TAIL_DATA_LEN: usize = 1000;
const DEAD_ENTRY_LEN: usize = 136; // dl=0 record, 8-aligned
const TAIL_ENTRY_LEN: usize = 136 + TAIL_DATA_LEN; // 1,136, 8-aligned
const FULL_LEN: u64 = DEAD_ENTRY_LEN + TAIL_ENTRY_LEN; // 1,272 = pre-shrink file (data ends at EOF)
const INCR_LEN: u64 = TAIL_ENTRY_LEN; // 1,136 = post-shrink layout (dead entry gone)

const PDA_PK: [32]u8 = [_]u8{0x12} ++ [_]u8{0x7e} ++ [_]u8{0xAA} ** 30; // 2FC547gL… stand-in
const PDA_OWNER: [32]u8 = [_]u8{0xf8} ++ [_]u8{0x75} ++ [_]u8{0xBB} ** 30; // HistoryJTG… stand-in
const PDA_LAMPORTS: u64 = 915_100_800;

fn appendRecord(buf: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, pk: [32]u8, lamports: u64, owner: [32]u8, data: []const u8) !void {
    var w64: [8]u8 = undefined;
    // StoredMeta: write_version(8) + data_len(8) + pubkey(32)
    std.mem.writeInt(u64, &w64, 0, .little);
    try buf.appendSlice(a, &w64);
    std.mem.writeInt(u64, &w64, @intCast(data.len), .little);
    try buf.appendSlice(a, &w64);
    try buf.appendSlice(a, &pk);
    // AccountMeta: lamports(8) + rent_epoch(8) + owner(32) + executable(1) + pad(7)
    std.mem.writeInt(u64, &w64, lamports, .little);
    try buf.appendSlice(a, &w64);
    std.mem.writeInt(u64, &w64, std.math.maxInt(u64), .little); // rent_epoch=MAX
    try buf.appendSlice(a, &w64);
    try buf.appendSlice(a, &owner);
    try buf.append(a, 0); // executable=false
    try buf.appendSlice(a, &[_]u8{0} ** 7);
    // Hash(32)
    try buf.appendSlice(a, &[_]u8{0} ** 32);
    // Data + pad to 8
    try buf.appendSlice(a, data);
    const record_len = 136 + data.len;
    const pad = (8 - (record_len % 8)) & 7;
    try buf.appendSlice(a, (&[_]u8{0} ** 7)[0..pad]);
}

/// Synthesize the carrier appendvec: entry0 = dead fee-payer (dl=0,
/// lamports=0, nonzero pk), entry1 = live PDA whose data ends EXACTLY at EOF.
fn buildCarrierAppendVec(a: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(a);
    const dead_pk = [_]u8{0x01} ** 32;
    try appendRecord(&buf, a, dead_pk, 0, [_]u8{0} ** 32, &[_]u8{});
    var pda_data: [TAIL_DATA_LEN]u8 = undefined;
    for (&pda_data, 0..) |*b, i| b.* = @truncate(i);
    try appendRecord(&buf, a, PDA_PK, PDA_LAMPORTS, PDA_OWNER, &pda_data);
    std.debug.assert(buf.items.len == FULL_LEN);
    return buf.toOwnedSlice(a);
}

const MockIndex = struct {
    a: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .{},
    pub const Entry = struct { pk: [32]u8, loc: accounts.AccountLocation };
    pub fn insert(self: *MockIndex, pk: *const core.Pubkey, loc: accounts.AccountLocation) !void {
        try self.entries.append(self.a, .{ .pk = pk.data, .loc = loc });
    }
    fn find(self: *const MockIndex, pk: [32]u8) ?accounts.AccountLocation {
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, &e.pk, &pk)) return e.loc;
        }
        return null;
    }
};

const MockDb = struct {
    index: MockIndex,
    next_id: u32 = 0,
    registered_len: u64 = 0,
    pub fn registerAgaveMmap(self: *MockDb, data: []u8, file_size: u64) !u32 {
        _ = data;
        self.registered_len = file_size;
        self.next_id += 1;
        return self.next_id;
    }
};

fn writeTmpAppendVec(tmp: *std.testing.TmpDir, a: std.mem.Allocator, bytes: []const u8, name: []const u8) ![]u8 {
    try tmp.dir.writeFile(.{ .sub_path = name, .data = bytes });
    const dir_path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir_path);
    return std.fs.path.join(a, &.{ dir_path, name });
}

test "snapload provenance: wrong (incremental) len on full-archive file — tail account recovered LOUDLY (carrier 414364417.1455839 shape; FAIL-before/PASS-after)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const av = try buildCarrierAppendVec(a);
    defer a.free(av);
    const path = try writeTmpAppendVec(&tmp, a, av, "414364417.1455839");
    defer a.free(path);

    var loader = parallel_snapshot.ParallelSnapshotLoader.init(a, .{ .num_threads = 1 });
    defer loader.deinit();
    var db = MockDb{ .index = .{ .a = a } };
    defer db.index.entries.deinit(a);

    // Pre-fix: data_end (1,272) > file_size (1,136) → silent break → PDA dropped.
    const res = try loader.mmapAndIndex(path, FILE_SLOT, INCR_LEN, &db);
    defer if (res.mmap_size > 0) std.posix.munmap(@as([*]align(4096) u8, @alignCast(res.mmap_ptr))[0..res.mmap_size]);

    const loc = db.index.find(PDA_PK) orelse return error.CarrierAccountDroppedAtSnapshotLoad;
    try std.testing.expectEqual(@as(u64, DEAD_ENTRY_LEN), loc.offset);
    try std.testing.expectEqual(FILE_SLOT, loc.slot);
    try std.testing.expectEqual(@as(u64, 1), res.accounts_indexed);
    try std.testing.expectEqual(PDA_LAMPORTS, res.lamports_total);
    // Recovery must be LOUD: mismatch counted, nothing skipped.
    try std.testing.expectEqual(@as(u64, 1), loader.len_mismatch_files.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), loader.accounts_recovered_len_mismatch.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loader.accounts_skipped_len_mismatch.load(.monotonic));
    // Store must be registered long enough to serve the recovered tail.
    try std.testing.expectEqual(FULL_LEN, db.registered_len);
}

test "snapload provenance: mergeFileSzMapsByProvenance keys by archive provenance (Agave get_storage_lengths_for_snapshot_slots)" {
    const a = std.testing.allocator;

    var full_map = snapshot_manifest.FileSzMap.init(a);
    defer full_map.deinit();
    try full_map.put(snapshot_manifest.fileKey(FILE_SLOT, FILE_ID), FULL_LEN);

    var incr_map = snapshot_manifest.FileSzMap.init(a);
    defer incr_map.deinit();
    // The carrier disagreement: incremental records the post-shrink len for a
    // full-archive storage it does NOT ship.
    try incr_map.put(snapshot_manifest.fileKey(FILE_SLOT, FILE_ID), INCR_LEN);
    // A genuine incremental storage (slot > full_slot): its len must survive.
    try incr_map.put(snapshot_manifest.fileKey(FULL_SLOT + 100, 99), 512);
    // An incremental entry for an old slot with no full-manifest counterpart:
    // must be DROPPED (Agave filters slot ≤ base_slot; stat-size fallback applies).
    try incr_map.put(snapshot_manifest.fileKey(FILE_SLOT - 400, 5), 64);

    var merged = try snapshot_manifest.mergeFileSzMapsByProvenance(a, FULL_SLOT, &full_map, &incr_map);
    defer merged.deinit();

    try std.testing.expectEqual(@as(?u64, FULL_LEN), merged.get(snapshot_manifest.fileKey(FILE_SLOT, FILE_ID)));
    try std.testing.expectEqual(@as(?u64, 512), merged.get(snapshot_manifest.fileKey(FULL_SLOT + 100, 99)));
    try std.testing.expectEqual(@as(?u64, null), merged.get(snapshot_manifest.fileKey(FILE_SLOT - 400, 5)));
    try std.testing.expectEqual(@as(u32, 2), merged.count());
}

test "snapload provenance: correct (full-manifest) len indexes the tail account with ZERO mismatch counters" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const av = try buildCarrierAppendVec(a);
    defer a.free(av);
    const path = try writeTmpAppendVec(&tmp, a, av, "414364417.1455839");
    defer a.free(path);

    var loader = parallel_snapshot.ParallelSnapshotLoader.init(a, .{ .num_threads = 1 });
    defer loader.deinit();
    var db = MockDb{ .index = .{ .a = a } };
    defer db.index.entries.deinit(a);

    const res = try loader.mmapAndIndex(path, FILE_SLOT, FULL_LEN, &db);
    defer if (res.mmap_size > 0) std.posix.munmap(@as([*]align(4096) u8, @alignCast(res.mmap_ptr))[0..res.mmap_size]);

    try std.testing.expect(db.index.find(PDA_PK) != null);
    try std.testing.expectEqual(@as(u64, 1), res.accounts_indexed);
    try std.testing.expectEqual(@as(u64, 0), loader.len_mismatch_files.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loader.accounts_recovered_len_mismatch.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loader.accounts_skipped_len_mismatch.load(.monotonic));
}

test "snapload provenance: zero padding beyond manifest len stays silent (healthy preallocation shape)" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(a);
    const pk = [_]u8{0x42} ** 32;
    try appendRecord(&buf, a, pk, 1_000, [_]u8{0x03} ** 32, &[_]u8{});
    const manifest_len: u64 = @intCast(buf.items.len); // 136
    try buf.appendSlice(a, &[_]u8{0} ** 64); // zero padding past manifest len

    const path = try writeTmpAppendVec(&tmp, a, buf.items, "1000.7");
    defer a.free(path);

    var loader = parallel_snapshot.ParallelSnapshotLoader.init(a, .{ .num_threads = 1 });
    defer loader.deinit();
    var db = MockDb{ .index = .{ .a = a } };
    defer db.index.entries.deinit(a);

    const res = try loader.mmapAndIndex(path, 1000, manifest_len, &db);
    defer if (res.mmap_size > 0) std.posix.munmap(@as([*]align(4096) u8, @alignCast(res.mmap_ptr))[0..res.mmap_size]);

    try std.testing.expect(db.index.find(pk) != null);
    try std.testing.expectEqual(@as(u64, 0), loader.len_mismatch_files.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loader.accounts_recovered_len_mismatch.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loader.accounts_skipped_len_mismatch.load(.monotonic));
    try std.testing.expectEqual(manifest_len, db.registered_len);
}
