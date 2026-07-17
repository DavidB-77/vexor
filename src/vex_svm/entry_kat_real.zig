//! entry.zig INTEGRATION KAT against a REAL captured testnet slot (task #27).
//!
//! Validates the canonical Entry module (entry.zig) on real on-chain data, not synthetic vectors:
//!   1. PARSER-INVERSE: walk a real deshredded entry buffer (the exact bytes replayEntries received,
//!      captured one-shot via VEX_DUMP_ENTRY → /tmp/vex_entry_<slot>.bin + .bnd boundaries sidecar),
//!      framing it identically to the replay parser (component boundaries → bincode Vec<Entry>).
//!   2. POH CHAIN: for every consecutive entry pair, assert
//!         entry[i].hash == entry.nextHash(entry[i-1].hash, entry[i].num_hashes, num_txs, sigs)
//!      i.e. reproduce each entry's PoH hash (incl. the signature-merkle record-mixin) from the prior
//!      entry's hash. N-1 independent nextHash+hashSignatures checks per slot — NO RPC needed.
//!   3. (optional anchor) if VEX_KAT_PREV / VEX_KAT_HASH (hex) are set from `getBlock`
//!      (previousBlockhash / blockhash), seed entry[0] from PREV and assert the final hash == HASH.
//!
//! Run:  VEX_KAT_ENTRY_FILE=/tmp/vex_entry_<slot>.bin VEX_KAT_BND_FILE=/tmp/vex_entry_<slot>.bnd \
//!       [VEX_KAT_PREV=<hex32> VEX_KAT_HASH=<hex32>] zig build test-entry-real
//! With no env set the test SKIPs (so it never fails a clean CI run without a capture).
//!
//! The VersionedTransaction walker (measureTransaction/readCompactU16) is ported verbatim from
//! replay_stage.zig:10745/10874 so the harness frames txs exactly as production does.

const std = @import("std");
const entry = @import("entry.zig");
const Hash = entry.Hash;

// ── ported tx walker (replay_stage.zig:10745 measureTransaction, :10874 readCompactU16) ──

fn readCompactU16(data: []const u8, pos: *usize) !u16 {
    if (pos.* >= data.len) return error.TooShort;
    var value: u32 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* + i >= data.len) return error.TooShort;
        const byte = data[pos.* + i];
        value |= @as(u32, byte & 0x7F) << @as(u5, @intCast(i * 7));
        if (byte & 0x80 == 0) {
            pos.* += i + 1;
            if (value > 65535) return error.TooShort;
            return @intCast(value);
        }
    }
    return error.TooShort;
}

/// Returns the byte length of the VersionedTransaction starting at `start`.
fn measureTransaction(data: []const u8, start: usize) error{TooShort}!usize {
    var pos = start;
    const num_sigs = readCompactU16(data, &pos) catch return error.TooShort;
    if (num_sigs == 0 or num_sigs > 127) return error.TooShort;
    const sigs_end = pos + @as(usize, num_sigs) * 64;
    if (sigs_end > data.len) return error.TooShort;
    pos = sigs_end;

    if (pos >= data.len) return error.TooShort;
    const is_versioned = (data[pos] & 0x80) != 0;
    if (is_versioned) {
        if ((data[pos] & 0x7F) != 0) return error.TooShort;
        pos += 1;
    }
    if (pos + 3 > data.len) return error.TooShort;
    pos += 3; // header

    const num_accounts = readCompactU16(data, &pos) catch return error.TooShort;
    if (num_accounts == 0 or num_accounts > 256) return error.TooShort;
    const accts_end = pos + @as(usize, num_accounts) * 32;
    if (accts_end > data.len) return error.TooShort;
    pos = accts_end;

    if (pos + 32 > data.len) return error.TooShort; // recent blockhash
    pos += 32;

    const num_ix = readCompactU16(data, &pos) catch return error.TooShort;
    if (num_ix > 255) return error.TooShort;
    for (0..num_ix) |_| {
        if (pos >= data.len) return error.TooShort;
        pos += 1; // program_id_index
        const nia = readCompactU16(data, &pos) catch return error.TooShort;
        if (pos + nia > data.len) return error.TooShort;
        pos += nia;
        const idl = readCompactU16(data, &pos) catch return error.TooShort;
        if (pos + idl > data.len) return error.TooShort;
        pos += idl;
    }
    if (is_versioned) {
        const nl = readCompactU16(data, &pos) catch return error.TooShort;
        if (nl > 127) return error.TooShort;
        for (0..nl) |_| {
            if (pos + 32 > data.len) return error.TooShort;
            pos += 32;
            const nw = readCompactU16(data, &pos) catch return error.TooShort;
            if (pos + nw > data.len) return error.TooShort;
            pos += nw;
            const nr = readCompactU16(data, &pos) catch return error.TooShort;
            if (pos + nr > data.len) return error.TooShort;
            pos += nr;
        }
    }
    return pos - start;
}

const ParsedEntry = struct {
    num_hashes: u64,
    hash: Hash,
    num_txs: u64,
    sigs: [][]const u8, // flat list of all this entry's txs' signatures (each 64B)
};

fn parseHex32(s: []const u8) ?Hash {
    if (s.len != 64) return null;
    var out: Hash = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

/// Parse the real entry buffer using the boundary-anchored framing (replay_stage.zig:4368+),
/// core path (complete slot: boundaries well-formed, last==data.len). Collects every entry.
fn parseEntries(
    allocator: std.mem.Allocator,
    data: []const u8,
    boundaries: []const u64,
) !std.ArrayListUnmanaged(ParsedEntry) {
    var entries: std.ArrayListUnmanaged(ParsedEntry) = .{};
    errdefer entries.deinit(allocator);

    const anchored = boundaries.len > 0;
    var comp_bi: usize = 0;
    var offset: usize = 0;

    while (offset + 8 <= data.len) {
        const comp_end: usize = if (anchored and comp_bi < boundaries.len)
            @intCast(boundaries[comp_bi])
        else
            data.len;

        // Read one bincode Vec<Entry> batch: u64 count, then `count` entries.
        if (offset + 8 > comp_end) {
            // range consumed → snap to boundary, advance.
            offset = comp_end;
            comp_bi += 1;
            if (!anchored or comp_bi > boundaries.len) break;
            if (comp_bi == boundaries.len and offset >= data.len) break;
            continue;
        }
        const count = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;
        if (count == 0 or count > 1_000_000) return error.BadCount;

        var e: usize = 0;
        while (e < count) : (e += 1) {
            if (offset + 8 + 32 + 8 > data.len) return error.Truncated;
            const num_hashes = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
            var h: Hash = undefined;
            @memcpy(&h, data[offset..][0..32]);
            offset += 32;
            const num_txs = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;

            var sigs: std.ArrayListUnmanaged([]const u8) = .{};
            var t: usize = 0;
            while (t < num_txs) : (t += 1) {
                const tx_start = offset;
                const tx_len = try measureTransaction(data, tx_start);
                // extract this tx's signatures: compact-u16 count then count*64.
                var sp = tx_start;
                const ns = try readCompactU16(data, &sp);
                var s: usize = 0;
                while (s < ns) : (s += 1) {
                    try sigs.append(allocator, data[sp..][0..64]);
                    sp += 64;
                }
                offset += tx_len;
            }
            try entries.append(allocator, .{
                .num_hashes = num_hashes,
                .hash = h,
                .num_txs = num_txs,
                .sigs = try sigs.toOwnedSlice(allocator),
            });
        }

        // After a batch: if anchored and we've reached the component end, snap + advance.
        if (anchored and comp_bi < boundaries.len and offset >= comp_end) {
            offset = comp_end;
            comp_bi += 1;
        }
    }
    return entries;
}

test "entry.zig vs REAL captured slot: per-entry PoH chain + optional blockhash anchor" {
    const allocator = std.testing.allocator;

    const bin_path = std.posix.getenv("VEX_KAT_ENTRY_FILE") orelse return error.SkipZigTest;
    const bnd_path = std.posix.getenv("VEX_KAT_BND_FILE");

    const data = std.fs.cwd().readFileAlloc(allocator, bin_path, 64 * 1024 * 1024) catch return error.SkipZigTest;
    defer allocator.free(data);

    var boundaries: []u64 = &.{};
    if (bnd_path) |bp| {
        const raw = std.fs.cwd().readFileAlloc(allocator, bp, 1024 * 1024) catch &[_]u8{};
        defer if (raw.len > 0) allocator.free(raw);
        if (raw.len >= 8) {
            const n = raw.len / 8;
            const arr = try allocator.alloc(u64, n);
            for (0..n) |i| arr[i] = std.mem.readInt(u64, raw[i * 8 ..][0..8], .little);
            boundaries = arr;
        }
    }
    defer if (boundaries.len > 0) allocator.free(boundaries);

    var entries = try parseEntries(allocator, data, boundaries);
    defer {
        for (entries.items) |it| allocator.free(it.sigs);
        entries.deinit(allocator);
    }

    try std.testing.expect(entries.items.len > 0);

    var ticks: usize = 0;
    var tx_entries: usize = 0;
    var total_txs: u64 = 0;
    for (entries.items) |it| {
        if (it.num_txs == 0) ticks += 1 else tx_entries += 1;
        total_txs += it.num_txs;
    }
    std.debug.print(
        "[KAT-REAL] entries={d} ticks={d} tx_entries={d} total_txs={d} boundaries={d} data_len={d}\n",
        .{ entries.items.len, ticks, tx_entries, total_txs, boundaries.len, data.len },
    );

    // ── Core: per-entry PoH chain (entry[i].hash reproduced from entry[i-1].hash). No RPC. ──
    var checked: usize = 0;
    var i: usize = 1;
    while (i < entries.items.len) : (i += 1) {
        const prev = entries.items[i - 1].hash;
        const cur = entries.items[i];
        const got = try entry.nextHash(allocator, prev, cur.num_hashes, @intCast(cur.num_txs), cur.sigs);
        if (!std.mem.eql(u8, &got, &cur.hash)) {
            std.debug.print(
                "[KAT-REAL] MISMATCH entry#{d} num_hashes={d} num_txs={d} sigs={d}\n  expected={s}\n  got     ={s}\n",
                .{ i, cur.num_hashes, cur.num_txs, cur.sigs.len, &std.fmt.bytesToHex(cur.hash, .lower), &std.fmt.bytesToHex(got, .lower) },
            );
            return error.PohChainMismatch;
        }
        checked += 1;
    }
    std.debug.print("[KAT-REAL] PoH-chain OK: {d}/{d} consecutive entry hashes reproduced\n", .{ checked, entries.items.len - 1 });
    try std.testing.expect(checked == entries.items.len - 1);

    // ── Optional anchor: seed entry[0] from getBlock previousBlockhash, final == blockhash. ──
    if (std.posix.getenv("VEX_KAT_PREV")) |prev_hex| {
        const prev = parseHex32(prev_hex) orelse return error.BadPrevHex;
        const e0 = entries.items[0];
        const h0 = try entry.nextHash(allocator, prev, e0.num_hashes, @intCast(e0.num_txs), e0.sigs);
        try std.testing.expectEqualSlices(u8, &e0.hash, &h0); // entry[0] reproduced from real prev blockhash
        const final = entries.items[entries.items.len - 1].hash;
        if (std.posix.getenv("VEX_KAT_HASH")) |bh_hex| {
            const bh = parseHex32(bh_hex) orelse return error.BadHashHex;
            try std.testing.expectEqualSlices(u8, &bh, &final); // last entry hash == cluster blockhash
            std.debug.print("[KAT-REAL] BLOCKHASH ANCHOR OK: final entry hash == getBlock blockhash\n", .{});
        }
    }
}
