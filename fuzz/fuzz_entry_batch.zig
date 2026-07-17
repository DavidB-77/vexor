//! Fuzz harness: entry-batch buffer walk (src/vex_svm/entry.zig + tx_ingest.zig).
//!
//! Untrusted-input surface: the deshredded entry-batch buffer that `replayEntries`
//! walks after FEC reassembly — the same raw-buffer surface the slot-422359406
//! incident's truncated block exercised. entry.zig owns the header framing
//! (`readEntryCount`/`readEntryHeader`); a tx-bearing entry's transaction bytes are
//! walked by the real tx_ingest parser plus a local compact-u16 instruction-list
//! skip (mirroring the documented wire format in tx_ingest.zig's own doc comment —
//! reimplemented here, not copied from anywhere) to find where each
//! VersionedTransaction ends and the next entry begins.
//!
//! No network, filesystem, or validator state required — pure in-memory decode.
const std = @import("std");
const entry = @import("entry");
const tx_ingest = @import("tx_ingest");

/// Read a compact-u16 (shortvec) at `buf[pos.*]`, advancing `pos`. Same 1–3 byte,
/// 7-bits-per-byte, high-bit-continuation format documented in tx_ingest.zig.
fn readCompactU16(buf: []const u8, pos: *usize) ?u16 {
    var val: u32 = 0;
    var shift: u5 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* >= buf.len) return null;
        const b = buf[pos.*];
        pos.* += 1;
        val |= @as(u32, b & 0x7f) << shift;
        if (b & 0x80 == 0) return @intCast(val & 0xffff);
        shift += 7;
    }
    return @intCast(val & 0xffff);
}

/// Given a tx_ingest.ParsedTx already anchored at `wire`, walk past its
/// instruction list (and, for a v0 message, its address_table_lookups) to find
/// the total consumed byte length of this one VersionedTransaction. Returns null
/// on any truncation/inconsistency — the caller stops walking the batch.
fn skipOneTransaction(wire: []const u8, ptx: tx_ingest.ParsedTx) ?usize {
    var pos = ptx.instructions_offset;
    if (pos > wire.len) return null;

    const num_ix = readCompactU16(wire, &pos) orelse return null;
    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (pos >= wire.len) return null;
        pos += 1; // program_id_index
        const num_accounts = readCompactU16(wire, &pos) orelse return null;
        if (pos + num_accounts > wire.len) return null;
        pos += num_accounts;
        const data_len = readCompactU16(wire, &pos) orelse return null;
        if (pos + data_len > wire.len) return null;
        pos += data_len;
    }

    if (ptx.is_versioned) {
        const num_luts = readCompactU16(wire, &pos) orelse return null;
        var j: u16 = 0;
        while (j < num_luts) : (j += 1) {
            if (pos + 32 > wire.len) return null;
            pos += 32; // lookup table account key
            const num_writable = readCompactU16(wire, &pos) orelse return null;
            if (pos + num_writable > wire.len) return null;
            pos += num_writable;
            const num_readonly = readCompactU16(wire, &pos) orelse return null;
            if (pos + num_readonly > wire.len) return null;
            pos += num_readonly;
        }
    }

    return pos;
}

pub fn fuzzOne(data: []const u8) void {
    const count = entry.readEntryCount(data) catch return;

    var offset: usize = 8; // past the u64 entry_count
    var n: u64 = 0;
    while (n < count and n < 10_000) : (n += 1) {
        const hdr = entry.readEntryHeader(data, offset) catch return;
        offset = hdr.txs_offset;

        var t: u64 = 0;
        while (t < hdr.num_txs and t < 10_000) : (t += 1) {
            if (offset >= data.len) return;
            const wire = data[offset..];

            var scratch_sigs: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var scratch_keys: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const ptx = tx_ingest.parse(wire, &scratch_sigs, &scratch_keys) catch return;

            const consumed = skipOneTransaction(wire, ptx) orelse return;
            if (consumed == 0) return; // no forward progress — stop rather than loop
            offset += consumed;
        }
    }
}

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    fuzzOne(data[0..len]);
    return 0;
}

test "fuzz: entry-batch walk survives arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn call(_: void, input: []const u8) anyerror!void {
            fuzzOne(input);
        }
    }.call, .{});
}
