//! test-snapshot-create — ROUND-TRIP KAT for snapshot CREATION (2026-06-21)
//!
//! Proves the write-side snapshot is LOADABLE by Vexor's OWN proven readers,
//! WITHOUT writing a full 30GB snapshot. The flow:
//!
//!   1. Build a small SYNTHETIC AccountsDb on disk: a handful of accounts in a
//!      single Agave-format AppendVec (`accounts/<slot>.0`), written with the
//!      SAME record layout `AccountsDb.writeSnapshotAppendVec` emits and the
//!      loader `parallel_snapshot.parseBuffer` consumes.
//!   2. Serialize a bank MANIFEST with known field values (bank_hash,
//!      capitalization, block_height, last_blockhash, hashes_per_tick, a REAL
//!      2048-byte accounts_lt_hash, block_id, and the storages map) via
//!      `snapshot_manifest.serializeManifest` + `writeManifestFile`.
//!   3. Write the empty status_cache stub.
//!   4. LOAD IT BACK with Vexor's proven readers:
//!        * `snapshot_manifest.parseManifest` (the live boot-path parser)
//!        * `parallel_snapshot.parseAppendVecWithSz` (the live mmap loader)
//!   5. ASSERT every manifest field round-trips AND every account reloads with
//!      identical pubkey/lamports/owner/executable/data.
//!
//! WHY POSITIVE ASSERTS: `parseManifestFromBytes` degrades GRACEFULLY — on a
//! desync it logs a warn and returns an EMPTY ManifestResult with NO error. So
//! "parseManifest returned ok" is a vacuous pass. Every assert below checks a
//! POSITIVE value (bank_hash == expected, lthash != null AND equals, file_sz
//! map non-empty AND correct, etc.), which is the only way a misaligned writer
//! is caught. The lthash-equality assert ALSO proves the canonical
//! forward-parser hit (not the tail-seek fallback), which requires the file to
//! end exactly after block_id.

const std = @import("std");
const vex_store = @import("vex_store");
const manifest = vex_store.snapshot_manifest;
const psnap = vex_store.parallel_snapshot;

// Agave AppendVec record layout (must match writeSnapshotAppendVec / parseBuffer).
const STORED_META_SIZE: usize = 48; // write_version(8) + data_len(8) + pubkey(32)
const ACCOUNT_META_SIZE: usize = 56; // lamports(8) + rent_epoch(8) + owner(32) + executable(1) + pad(7)
const HASH_SIZE: usize = 32;

const SynthAccount = struct {
    pubkey: [32]u8,
    lamports: u64,
    rent_epoch: u64,
    owner: [32]u8,
    executable: bool,
    data: []const u8,
};

/// Write one synthetic account record in Agave AppendVec format. Returns the
/// total record length (including padding) so the caller can track file size.
fn writeRecord(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, a: SynthAccount) !usize {
    var b8: [8]u8 = undefined;
    const start = buf.items.len;
    // StoredMeta
    std.mem.writeInt(u64, &b8, 0, .little); // write_version (obsolete, 0)
    try buf.appendSlice(alloc, &b8);
    std.mem.writeInt(u64, &b8, @intCast(a.data.len), .little); // data_len
    try buf.appendSlice(alloc, &b8);
    try buf.appendSlice(alloc, &a.pubkey);
    // AccountMeta
    std.mem.writeInt(u64, &b8, a.lamports, .little);
    try buf.appendSlice(alloc, &b8);
    std.mem.writeInt(u64, &b8, a.rent_epoch, .little);
    try buf.appendSlice(alloc, &b8);
    try buf.appendSlice(alloc, &a.owner);
    try buf.append(alloc, @intFromBool(a.executable));
    try buf.appendNTimes(alloc, 0, 7); // pad
    // Hash (32, zeros for local snapshot)
    try buf.appendNTimes(alloc, 0, HASH_SIZE);
    // Data
    try buf.appendSlice(alloc, a.data);
    // Pad to 8-byte boundary
    const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + a.data.len;
    const pad = (8 - (record_len % 8)) & 7;
    if (pad != 0) try buf.appendNTimes(alloc, 0, pad);
    return buf.items.len - start;
}

test "snapshot-create round-trip: manifest + appendvec load back correctly" {
    const alloc = std.testing.allocator;

    // ── Synthetic fixture parameters ────────────────────────────────────────
    const slot: u64 = 416_900_000;
    const av_id: u64 = 7;
    const parent_slot: u64 = slot - 1;

    var bank_hash: [32]u8 = undefined;
    for (&bank_hash, 0..) |*x, i| x.* = @intCast((i * 7 + 3) & 0xff);
    var parent_hash: [32]u8 = undefined;
    for (&parent_hash, 0..) |*x, i| x.* = @intCast((i * 11 + 5) & 0xff);
    var last_blockhash: [32]u8 = undefined;
    for (&last_blockhash, 0..) |*x, i| x.* = @intCast((i * 13 + 1) & 0xff);
    var block_id: [32]u8 = undefined;
    for (&block_id, 0..) |*x, i| x.* = @intCast((i * 17 + 9) & 0xff);

    const capitalization: u64 = 123_456_789_000;
    const block_height: u64 = 368_000_000;
    const hashes_per_tick: u64 = 62500;
    const ticks_per_slot: u64 = 64;
    const epoch: u64 = 977;

    // REAL lthash: a fully-populated 2048-byte value (NOT the simple
    // accounts_hash). Synthesized deterministically here; on the live path this
    // is bank.accounts_lthash.asBytes() ([BANK-FROZEN] lthash_full).
    var lthash: [2048]u8 = undefined;
    for (&lthash, 0..) |*x, i| x.* = @intCast((i * 31 + 17) & 0xff);

    // Synthetic accounts (non-zero lamports — full-snapshot zero-lamport records
    // are skipped by the loader).
    var owner_a: [32]u8 = [_]u8{0} ** 32;
    owner_a[0] = 0x02; // SystemProgram-ish marker
    var owner_b: [32]u8 = [_]u8{0} ** 32;
    owner_b[31] = 0xAB;

    var pk0: [32]u8 = undefined;
    for (&pk0, 0..) |*x, i| x.* = @intCast((i + 1) & 0xff);
    var pk1: [32]u8 = undefined;
    for (&pk1, 0..) |*x, i| x.* = @intCast((200 - i) & 0xff);
    var pk2: [32]u8 = undefined;
    for (&pk2, 0..) |*x, i| x.* = @intCast((i * 3 + 50) & 0xff);

    const accounts = [_]SynthAccount{
        .{ .pubkey = pk0, .lamports = 1_000_000, .rent_epoch = 18446744073709551615, .owner = owner_a, .executable = false, .data = &[_]u8{} },
        .{ .pubkey = pk1, .lamports = 42, .rent_epoch = 0, .owner = owner_b, .executable = true, .data = "hello-vexor-snapshot" },
        .{ .pubkey = pk2, .lamports = 999_999_999, .rent_epoch = 100, .owner = owner_a, .executable = false, .data = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 } },
    };

    // ── Build the snapshot directory layout on disk ─────────────────────────
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(root);

    const snap_dir = try std.fmt.allocPrint(alloc, "{s}/local-snapshot-{d}", .{ root, slot });
    defer alloc.free(snap_dir);

    // accounts/ and snapshots/<slot>/
    {
        const acc_dir = try std.fmt.allocPrint(alloc, "{s}/accounts", .{snap_dir});
        defer alloc.free(acc_dir);
        try std.fs.cwd().makePath(acc_dir);
        const snaps_slot_dir = try std.fmt.allocPrint(alloc, "{s}/snapshots/{d}", .{ snap_dir, slot });
        defer alloc.free(snaps_slot_dir);
        try std.fs.cwd().makePath(snaps_slot_dir);
    }

    // version file
    {
        const vpath = try std.fmt.allocPrint(alloc, "{s}/version", .{snap_dir});
        defer alloc.free(vpath);
        const vf = try std.fs.cwd().createFile(vpath, .{ .truncate = true });
        defer vf.close();
        try vf.writeAll("1.3.1\n");
    }

    // ── Write the synthetic AppendVec: accounts/<slot>.<id> ─────────────────
    var av_buf = std.ArrayListUnmanaged(u8){};
    defer av_buf.deinit(alloc);
    var expected_lamports: u64 = 0;
    for (accounts) |a| {
        _ = try writeRecord(&av_buf, alloc, a);
        expected_lamports += a.lamports;
    }
    const av_path = try std.fmt.allocPrint(alloc, "{s}/accounts/{d}.{d}", .{ snap_dir, slot, av_id });
    defer alloc.free(av_path);
    {
        const avf = try std.fs.cwd().createFile(av_path, .{ .truncate = true });
        defer avf.close();
        try avf.writeAll(av_buf.items);
    }
    // The REAL on-disk byte count — this is the file_sz the manifest must record
    // (NOT accounts_written). Stat the file we just wrote.
    const av_file_sz: u64 = blk: {
        const f = try std.fs.cwd().openFile(av_path, .{});
        defer f.close();
        const st = try f.stat();
        break :blk st.size;
    };
    try std.testing.expectEqual(@as(u64, av_buf.items.len), av_file_sz);

    // ── Synthetic epoch_stakes (KNOWN set across 2 epochs) ──────────────────
    // Epoch 977: 3 vote accounts on 2 nodes (nodeA hosts vote0+vote1, nodeB
    // hosts vote2). Epoch 978: 1 vote account on nodeA. Distinct stakes +
    // distinct node_pubkeys + distinct commission_bps so every captured field
    // round-trips to a UNIQUE value (a mis-aligned writer can't alias-pass).
    var nodeA: [32]u8 = undefined;
    for (&nodeA, 0..) |*x, i| x.* = @intCast((i * 5 + 1) & 0xff);
    var nodeB: [32]u8 = undefined;
    for (&nodeB, 0..) |*x, i| x.* = @intCast((i * 9 + 2) & 0xff);
    var vote0: [32]u8 = undefined;
    for (&vote0, 0..) |*x, i| x.* = @intCast((i + 100) & 0xff);
    var vote1: [32]u8 = undefined;
    for (&vote1, 0..) |*x, i| x.* = @intCast((i + 150) & 0xff);
    var vote2: [32]u8 = undefined;
    for (&vote2, 0..) |*x, i| x.* = @intCast((i + 200) & 0xff);

    var es977_stakes = [_]manifest.VoteAccountStake{
        .{ .vote_pubkey = vote0, .stake = 1_111 },
        .{ .vote_pubkey = vote1, .stake = 2_222 },
        .{ .vote_pubkey = vote2, .stake = 3_333 },
    };
    var es977_nodes = [_][32]u8{ nodeA, nodeA, nodeB };
    var es977_comm_pct = [_]u8{ 5, 7, 10 };
    var es977_comm_bps = [_]u16{ 500, 700, 1000 };

    var es978_stakes = [_]manifest.VoteAccountStake{
        .{ .vote_pubkey = vote0, .stake = 4_444 },
    };
    var es978_nodes = [_][32]u8{nodeA};
    var es978_comm_pct = [_]u8{3};
    var es978_comm_bps = [_]u16{300};

    const epoch_stakes = [_]manifest.EpochStakesEntry{
        .{
            .epoch = 977,
            .vote_account_stakes = &es977_stakes,
            .node_pubkeys = &es977_nodes,
            .commission_percent = &es977_comm_pct,
            .commission_bps = &es977_comm_bps,
        },
        .{
            .epoch = 978,
            .vote_account_stakes = &es978_stakes,
            .node_pubkeys = &es978_nodes,
            .commission_percent = &es978_comm_pct,
            .commission_bps = &es978_comm_bps,
        },
    };

    // ── Serialize + write the MANIFEST ──────────────────────────────────────
    const storages = [_]manifest.StorageEntry{
        .{ .slot = slot, .id = av_id, .file_sz = av_file_sz },
    };
    const wfields = manifest.ManifestWriteFields{
        .slot = slot,
        .parent_slot = parent_slot,
        .bank_hash = bank_hash,
        .parent_hash = parent_hash,
        .last_blockhash = last_blockhash,
        .capitalization = capitalization,
        .block_height = block_height,
        .hashes_per_tick = hashes_per_tick,
        .ticks_per_slot = ticks_per_slot,
        .epoch = epoch,
        .accounts_lt_hash = lthash,
        .block_id = block_id,
        .storages = &storages,
        .epoch_stakes = &epoch_stakes,
    };
    const manifest_bytes_written = try manifest.writeManifestFile(alloc, snap_dir, wfields);
    try std.testing.expect(manifest_bytes_written > 0);

    // status_cache stub
    try manifest.writeStatusCacheFile(snap_dir);

    // ── ROUND-TRIP (a): reload the manifest with the LIVE boot-path parser ──
    var result = try manifest.parseManifest(alloc, snap_dir, slot);
    defer {
        result.file_sz_map.deinit();
        // free owned slices
        if (result.vote_account_stakes.len > 0) alloc.free(result.vote_account_stakes);
        for (result.vote_frozen_data) |fd| if (fd.len > 0) alloc.free(@constCast(fd));
        if (result.vote_frozen_data.len > 0) alloc.free(@constCast(result.vote_frozen_data));
        for (result.epoch_stakes) |es| {
            if (es.vote_account_stakes.len > 0) alloc.free(es.vote_account_stakes);
            if (es.node_pubkeys.len > 0) alloc.free(@constCast(es.node_pubkeys));
            if (es.commission_percent.len > 0) alloc.free(@constCast(es.commission_percent));
            if (es.commission_bps.len > 0) alloc.free(@constCast(es.commission_bps));
        }
        if (result.epoch_stakes.len > 0) alloc.free(@constCast(result.epoch_stakes));
        if (result.hard_forks.len > 0) alloc.free(@constCast(result.hard_forks));
    }

    // POSITIVE asserts — guard against the empty-ManifestResult graceful path.
    try std.testing.expect(result.bank_hash != null);
    try std.testing.expectEqualSlices(u8, &bank_hash, &result.bank_hash.?);
    try std.testing.expectEqual(@as(?u64, capitalization), result.capitalization);
    try std.testing.expectEqual(@as(?u64, block_height), result.block_height);
    try std.testing.expectEqual(@as(?u64, hashes_per_tick), result.hashes_per_tick);
    try std.testing.expectEqual(ticks_per_slot, result.ticks_per_slot);
    try std.testing.expect(result.last_blockhash != null);
    try std.testing.expectEqualSlices(u8, &last_blockhash, &result.last_blockhash.?);
    // block_id round-trip (SIMD-0340 chained id).
    try std.testing.expect(result.block_id != null);
    try std.testing.expectEqualSlices(u8, &block_id, &result.block_id.?);
    // accounts_lt_hash MUST be present AND equal — proves the forward-parser hit
    // (the file ended exactly after block_id) and the REAL lthash round-tripped.
    try std.testing.expect(result.accounts_lt_hash != null);
    try std.testing.expectEqualSlices(u8, &lthash, &result.accounts_lt_hash.?);
    // storages map: non-empty AND the (slot,id) entry equals the real file_sz.
    try std.testing.expect(result.file_sz_map.count() > 0);
    const got_sz = result.file_sz_map.get(manifest.fileKey(slot, av_id));
    try std.testing.expect(got_sz != null);
    try std.testing.expectEqual(av_file_sz, got_sz.?);

    // ── epoch_stakes round-trip (CAPTURED subset via the LIVE reader) ───────
    // The live reader (readVersionedEpochStakesVecCapturing) captures, per vote
    // account: {vote_pubkey, stake, node_pubkey, commission_percent,
    // commission_bps}. Assert all of them round-trip byte-exact for both epochs.
    // NOTE: the fact that the lthash + block_id asserts ABOVE pass already proves
    // the (variable-length) epoch_stakes block is byte-exact — those fields come
    // AFTER versioned_epoch_stakes in the stream, so a 1-byte drift here shifts
    // them and fails. These asserts additionally prove the CONTENT is correct.
    try std.testing.expectEqual(@as(usize, 2), result.epoch_stakes.len);
    {
        // Match by epoch (reader preserves order, but match defensively).
        var seen977 = false;
        var seen978 = false;
        for (result.epoch_stakes) |got| {
            if (got.epoch == 977) {
                seen977 = true;
                try std.testing.expectEqual(@as(usize, 3), got.vote_account_stakes.len);
                for (es977_stakes, 0..) |exp, i| {
                    try std.testing.expectEqualSlices(u8, &exp.vote_pubkey, &got.vote_account_stakes[i].vote_pubkey);
                    try std.testing.expectEqual(exp.stake, got.vote_account_stakes[i].stake);
                    try std.testing.expectEqualSlices(u8, &es977_nodes[i], &got.node_pubkeys[i]);
                    try std.testing.expectEqual(es977_comm_pct[i], got.commission_percent[i]);
                    try std.testing.expectEqual(es977_comm_bps[i], got.commission_bps[i]);
                }
            } else if (got.epoch == 978) {
                seen978 = true;
                try std.testing.expectEqual(@as(usize, 1), got.vote_account_stakes.len);
                try std.testing.expectEqualSlices(u8, &vote0, &got.vote_account_stakes[0].vote_pubkey);
                try std.testing.expectEqual(@as(u64, 4_444), got.vote_account_stakes[0].stake);
                try std.testing.expectEqualSlices(u8, &nodeA, &got.node_pubkeys[0]);
                try std.testing.expectEqual(@as(u8, 3), got.commission_percent[0]);
                try std.testing.expectEqual(@as(u16, 300), got.commission_bps[0]);
            }
        }
        try std.testing.expect(seen977 and seen978);
    }

    // ── epoch_stakes round-trip (BOOT subset via a TEST-LOCAL reader) ───────
    // The live reader SKIPS total_stake + node_id_to_vote_accounts (it only
    // needs the per-vote table). Those maps ARE what a leader schedule boots
    // from, so re-read them here from the serialized bytes and assert the REAL
    // values: total_stake = sum of stakes; node_id_to_vote_accounts groups by
    // node_pubkey with node_stake = sum of that node's votes.
    {
        const raw = try manifest.serializeManifest(alloc, wfields);
        defer alloc.free(raw);
        const boot = try manifest.readEpochStakesBootSubsetForTest(alloc, raw);
        defer {
            for (boot) |b| alloc.free(b.nodes);
            alloc.free(boot);
        }
        try std.testing.expectEqual(@as(usize, 2), boot.len);
        for (boot) |b| {
            if (b.epoch == 977) {
                try std.testing.expectEqual(@as(u64, 1_111 + 2_222 + 3_333), b.total_stake);
                // 2 nodes: nodeA (vote0+vote1 = 3_333), nodeB (vote2 = 3_333).
                try std.testing.expectEqual(@as(usize, 2), b.nodes.len);
                var foundA = false;
                var foundB = false;
                for (b.nodes) |nd| {
                    if (std.mem.eql(u8, &nd.node, &nodeA)) {
                        foundA = true;
                        try std.testing.expectEqual(@as(u64, 1_111 + 2_222), nd.node_stake);
                        try std.testing.expectEqual(@as(usize, 2), nd.vote_count);
                    } else if (std.mem.eql(u8, &nd.node, &nodeB)) {
                        foundB = true;
                        try std.testing.expectEqual(@as(u64, 3_333), nd.node_stake);
                        try std.testing.expectEqual(@as(usize, 1), nd.vote_count);
                    }
                }
                try std.testing.expect(foundA and foundB);
            } else if (b.epoch == 978) {
                try std.testing.expectEqual(@as(u64, 4_444), b.total_stake);
                try std.testing.expectEqual(@as(usize, 1), b.nodes.len);
                try std.testing.expectEqualSlices(u8, &nodeA, &b.nodes[0].node);
                try std.testing.expectEqual(@as(u64, 4_444), b.nodes[0].node_stake);
                try std.testing.expectEqual(@as(usize, 1), b.nodes[0].vote_count);
            }
        }
    }

    // ── ROUND-TRIP (b): reload accounts with the LIVE mmap loader ───────────
    var loader = psnap.ParallelSnapshotLoader.init(alloc, .{ .num_threads = 1 });
    defer loader.deinit();
    var parsed = try loader.parseAppendVecWithSz(av_path, slot, got_sz.?);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, accounts.len), parsed.accounts.len);
    try std.testing.expectEqual(expected_lamports, parsed.lamports_total);

    // Every account reloads with identical pubkey/lamports/owner/executable/data.
    // Match by pubkey (loader preserves file order, but match defensively).
    for (accounts) |expected| {
        var found = false;
        for (parsed.accounts) |got| {
            if (std.mem.eql(u8, &got.pubkey, &expected.pubkey)) {
                found = true;
                try std.testing.expectEqual(expected.lamports, got.lamports);
                try std.testing.expectEqual(expected.rent_epoch, got.rent_epoch);
                try std.testing.expectEqualSlices(u8, &expected.owner, &got.owner);
                try std.testing.expectEqual(expected.executable, got.executable);
                try std.testing.expectEqualSlices(u8, expected.data, got.data);
                break;
            }
        }
        try std.testing.expect(found);
    }

    // ── ROUND-TRIP (c): tiny END-TO-END tar.zst create → extract → reload ───
    // Package the layout with the SAME shell-tar/zstd-T0 approach saveFullSnapshot
    // uses, extract to a fresh dir, and reload the MANIFEST from the extracted
    // copy. Proves the tar.zst artifact is itself loadable. Skipped gracefully if
    // tar/zstd are unavailable in the sandbox.
    e2e: {
        const dir_name = try std.fmt.allocPrint(alloc, "local-snapshot-{d}", .{slot});
        defer alloc.free(dir_name);
        const tar_path = try std.fmt.allocPrint(alloc, "{s}/snapshot-{d}-test.tar.zst", .{ root, slot });
        defer alloc.free(tar_path);
        {
            var child = std.process.Child.init(
                &.{ "tar", "--use-compress-program", "zstd -T0", "-cf", tar_path, "-C", root, dir_name },
                alloc,
            );
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            child.spawn() catch break :e2e;
            const term = child.wait() catch break :e2e;
            if (term != .Exited or term.Exited != 0) break :e2e;
        }
        const extract_root = try std.fmt.allocPrint(alloc, "{s}/extracted", .{root});
        defer alloc.free(extract_root);
        try std.fs.cwd().makePath(extract_root);
        {
            var child = std.process.Child.init(
                &.{ "tar", "--use-compress-program", "zstd -T0 -d", "-xf", tar_path, "-C", extract_root },
                alloc,
            );
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            child.spawn() catch break :e2e;
            const term = child.wait() catch break :e2e;
            if (term != .Exited or term.Exited != 0) break :e2e;
        }
        const extracted_snap_dir = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ extract_root, dir_name });
        defer alloc.free(extracted_snap_dir);

        var r2 = try manifest.parseManifest(alloc, extracted_snap_dir, slot);
        defer {
            r2.file_sz_map.deinit();
            if (r2.vote_account_stakes.len > 0) alloc.free(r2.vote_account_stakes);
            for (r2.vote_frozen_data) |fd| if (fd.len > 0) alloc.free(@constCast(fd));
            if (r2.vote_frozen_data.len > 0) alloc.free(@constCast(r2.vote_frozen_data));
            for (r2.epoch_stakes) |es| {
                if (es.vote_account_stakes.len > 0) alloc.free(es.vote_account_stakes);
                if (es.node_pubkeys.len > 0) alloc.free(@constCast(es.node_pubkeys));
                if (es.commission_percent.len > 0) alloc.free(@constCast(es.commission_percent));
                if (es.commission_bps.len > 0) alloc.free(@constCast(es.commission_bps));
            }
            if (r2.epoch_stakes.len > 0) alloc.free(@constCast(r2.epoch_stakes));
            if (r2.hard_forks.len > 0) alloc.free(@constCast(r2.hard_forks));
        }
        try std.testing.expect(r2.bank_hash != null);
        try std.testing.expectEqualSlices(u8, &bank_hash, &r2.bank_hash.?);
        try std.testing.expect(r2.accounts_lt_hash != null);
        try std.testing.expectEqualSlices(u8, &lthash, &r2.accounts_lt_hash.?);
        try std.testing.expect(r2.file_sz_map.get(manifest.fileKey(slot, av_id)) != null);
    }
}
