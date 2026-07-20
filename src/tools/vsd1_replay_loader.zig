//! shred-replay (`vsd1_replay_loader.zig`) — offline LOADER for captured raw
//! shred-buffer dumps, so real incident captures become permanent regression
//! tests without needing a live cluster or a full node boot.
//!
//! Born from incident-422359406 (2026-07-16, see design-doc
//! SWITCHPROOF-PART2-IMPLEMENTATION-PLAN-2026-07-16.md gate item 2 and memory
//! incident-422359406-fec-datacomplete-truncation-2026-07-16.md): slot 422359406
//! arrived truncated, was correctly refused by the blocking tick-gate, and its
//! raw buffer was captured to forensics — but there was NO reader for either of
//! the two dump formats the live binary produces on a replay failure
//! (replay_stage.zig replayEntries' catch branch, ~line 7160-7220):
//!
//!   1. `/tmp/vex_slot_<slot>_fail.bin` — the raw ASSEMBLED ENTRY BUFFER (the
//!      `data` argument to replayEntries itself: a bincode-ish `u64 count,
//!      then per-entry [u64 num_hashes][32]hash[u64 num_txs][tx bytes...]`
//!      stream — see entry.zig's "Entry-batch wire format" doc). No magic
//!      header; this is the OLDER of the two dumps and predates VSD1.
//!   2. `/tmp/vex_slot_<slot>_shreds.bin` (VSD1) — the raw PER-SHRED records
//!      with FEC-recovery provenance + component boundaries, written by
//!      `ShredAssembler.dumpSlotShredsWithProvenance` (shred_assembler.zig
//!      ~line 2016). Format documented at shred_assembler.zig:1992-2015.
//!
//! This tool auto-detects which of the two a file is (magic "VSD1" vs not),
//! and for either one reconstructs (or in the fail.bin case, already HAS) the
//! assembled entry-buffer bytes, then walks it with the SAME entry/tick
//! accounting the live replay path uses, reporting the exact verdict the live
//! binary would have reached: assembled/failed-at-X, tick-count,
//! DATA_COMPLETE flags seen, and whether the tick-gate would refuse it.
//!
//! REUSE, NOT REINVENT (tool-only; zero validator runtime changes):
//!   - Shred assembly (VSD1 path): the REAL production `ShredAssembler`
//!     (`vex_network.shred_pub.ShredAssembler`) + `parseShred` — the exact
//!     code the live TVU/repair ingest path runs, imported unmodified.
//!   - Tick-validity semantics: the REAL `verify_ticks.zig` `Verifier` (the
//!     module's own header: "the SINGLE SOURCE OF TRUTH... the live consensus
//!     path and the KAT exercise the exact same code, not two copies"),
//!     imported unmodified as a standalone module (it is std-only, no
//!     build_options dependency by design).
//!   - Transaction-length measurement (to skip over tx-bearing entries while
//!     walking the buffer): the REAL, already-`pub`, `replay_stage.zig`
//!     `measureTransaction` — reused via the standard `vex_svm` umbrella
//!     import (same "module-cycle dodge" pattern `vexor-program-test` and the
//!     `test-commit-owner-*` KATs already use for this exact tree). ZERO
//!     edits to replay_stage.zig.
//!
//! What IS new tool code (necessarily — `replayEntriesInternal` is entangled
//! with `Bank`/`AccountsDb`/tx execution/DAG dispatch and cannot be extracted
//! as a pure function without touching the runtime file): the OUTER
//! byte-offset walk that frames Vec<Entry> batches within component
//! boundaries and calls the three reused pieces above in sequence. It is a
//! faithful, comment-cited port of the pure offset arithmetic in
//! `replay_stage.zig` `replayEntriesInternal`'s `batch_loop`
//! (~lines 8064-8330) and the post-loop TooFewTicks flat gate
//! (~lines 9483-9495) — no Bank, no tx execution, no side effects.
//!
//! Usage:
//!   zig build shred-replay -- <dump-file> [--slot N]
//!
//! `--slot` is required only for the fail.bin (non-VSD1) format when the
//! filename doesn't already encode it as `vex_slot_<N>_fail.bin`.

const std = @import("std");
const vex_network = @import("vex_network");
const vex_svm = @import("vex_svm");
const verify_ticks = vex_svm.verify_ticks;

const shred_pub = vex_network.shred_pub;
const measureTransaction = vex_svm.replay_stage.measureTransaction;

// Keep the production ShredAssembler's chatty std.log.info shred-by-shred
// noise out of this CLI's stderr; warnings (e.g. FEC-DATACOMPLETE-OBSERVE)
// still surface.
pub const std_options: std.Options = .{ .log_level = .warn };

// ═══════════════════════════════════════════════════════════════════════════
// Format detection + VSD1 parsing
// ═══════════════════════════════════════════════════════════════════════════

pub const Format = enum { vsd1, raw_entry_buffer };

pub fn detectFormat(bytes: []const u8) Format {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "VSD1")) return .vsd1;
    return .raw_entry_buffer;
}

pub const RawShredRecord = struct {
    index: u32,
    recovered: bool,
    wire: []const u8,
};

pub const Vsd1File = struct {
    slot: u64,
    /// Boundaries as originally captured by dumpSlotShredsWithProvenance
    /// (offsets into the ORIGINAL failed replay's assembled buffer) — kept
    /// for cross-check logging only; the loader re-derives fresh boundaries
    /// from the re-assembled buffer rather than trusting these blindly.
    captured_boundaries: []const u64,
    records: []const RawShredRecord,
};

pub const Vsd1ParseError = error{ Truncated, BadMagic, BadVersion } || std.mem.Allocator.Error;

/// Parse the VSD1 wire format (shred_assembler.zig:1992-2015, all integers LE):
///   magic "VSD1"(4) version:u8=1 slot:u64 num_boundaries:u32 boundaries:u64[n]
///   num_records:u32 records:{ index:u32 recovered:u8 len:u16 payload:len }[n]
pub fn parseVsd1(allocator: std.mem.Allocator, bytes: []const u8) Vsd1ParseError!Vsd1File {
    if (bytes.len < 4 + 1 + 8 + 4) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], "VSD1")) return error.BadMagic;
    var o: usize = 4;
    const version = bytes[o];
    o += 1;
    if (version != 1) return error.BadVersion;

    const slot_val = std.mem.readInt(u64, bytes[o..][0..8], .little);
    o += 8;

    const num_boundaries = std.mem.readInt(u32, bytes[o..][0..4], .little);
    o += 4;
    var boundaries = try allocator.alloc(u64, num_boundaries);
    errdefer allocator.free(boundaries);
    for (0..num_boundaries) |i| {
        if (o + 8 > bytes.len) return error.Truncated;
        boundaries[i] = std.mem.readInt(u64, bytes[o..][0..8], .little);
        o += 8;
    }

    if (o + 4 > bytes.len) return error.Truncated;
    const num_records = std.mem.readInt(u32, bytes[o..][0..4], .little);
    o += 4;
    var records = try allocator.alloc(RawShredRecord, num_records);
    errdefer allocator.free(records);
    for (0..num_records) |i| {
        if (o + 4 + 1 + 2 > bytes.len) return error.Truncated;
        const idx = std.mem.readInt(u32, bytes[o..][0..4], .little);
        o += 4;
        const recovered = bytes[o] != 0;
        o += 1;
        const len = std.mem.readInt(u16, bytes[o..][0..2], .little);
        o += 2;
        if (o + len > bytes.len) return error.Truncated;
        records[i] = .{ .index = idx, .recovered = recovered, .wire = bytes[o..][0..len] };
        o += len;
    }

    return .{ .slot = slot_val, .captured_boundaries = boundaries, .records = records };
}

// ═══════════════════════════════════════════════════════════════════════════
// VSD1 path: reconstruct the assembled buffer via the REAL ShredAssembler
// ═══════════════════════════════════════════════════════════════════════════

pub const AssembleOutcome = struct {
    data: []u8,
    boundaries: []usize,
    shreds_inserted: usize,
    shreds_recovered_provenance: usize,
    completed_at_index: ?u32,
};

pub const AssembleError = error{
    SlotNeverCompleted,
} || std.mem.Allocator.Error || anyerror;

/// Feed every data-shred record through the production `ShredAssembler`
/// exactly as the live TVU insert path does (parseShred → insert), then pull
/// the assembled buffer + FRESH component boundaries via the same
/// `getAssembledDataWithBoundaries` the live replay path calls. Reproduces
/// whatever completion/truncation the live node saw, since the input is the
/// live node's own received-shred set (byte-for-byte, including any spurious
/// flag that triggered early completion).
pub fn assembleFromShreds(allocator: std.mem.Allocator, slot_val: u64, records: []const RawShredRecord) AssembleError!AssembleOutcome {
    var assembler = try shred_pub.ShredAssembler.init(allocator);
    defer assembler.deinit();

    var inserted: usize = 0;
    var recovered_count: usize = 0;
    var completed_at: ?u32 = null;
    for (records) |rec| {
        if (rec.recovered) recovered_count += 1;
        const shred = shred_pub.parseShred(rec.wire) catch |e| {
            std.log.warn("[shred-replay] parseShred FAILED idx={d} len={d}: {any} (skipping record)", .{ rec.index, rec.wire.len, e });
            continue;
        };
        const res = assembler.insert(shred) catch |e| {
            std.log.warn("[shred-replay] assembler.insert FAILED idx={d}: {any}", .{ rec.index, e });
            continue;
        };
        inserted += 1;
        if (res == .completed_slot) completed_at = rec.index;
    }

    if (!assembler.isSlotComplete(slot_val)) {
        return error.SlotNeverCompleted;
    }

    const ar = try assembler.getAssembledDataWithBoundaries(slot_val);
    return .{
        .data = ar.data,
        .boundaries = ar.boundaries,
        .shreds_inserted = inserted,
        .shreds_recovered_provenance = recovered_count,
        .completed_at_index = completed_at,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry/tick walk — faithful port of replay_stage.zig replayEntriesInternal's
// batch_loop (~8064-8330) + the post-loop flat TooFewTicks gate (~9483-9495).
// Pure byte-offset accounting: NO Bank, NO AccountsDb, NO tx execution.
// ═══════════════════════════════════════════════════════════════════════════

pub const StopReason = enum {
    /// Walked to the end of `data` (or all boundaries) with no fatal gate hit.
    exhausted,
    /// GATE1 (replay_stage.zig:8159): entry count prefix > 1,000,000 and no
    /// boundary to jump to — matches the live "break" (no legacy fallback for
    /// this gate — asymmetric with the 0-count case, faithfully preserved).
    bad_count_prefix,
    /// GATE2 (replay_stage.zig:8236, unanchored only): first entry's
    /// num_hashes peek was 0 or >5,000,000 at a non-zero offset.
    bad_first_num_hashes_peek,
    /// GATE3 (replay_stage.zig:8256, unanchored only): first entry's num_txs
    /// peek exceeded 10,000.
    bad_first_num_txs_peek,
    /// In-entry num_hashes > 5,000,000 (replay_stage.zig:8276).
    suspicious_num_hashes,
    /// In-entry num_txs > 10,000 (replay_stage.zig:8306).
    corrupt_num_txs,
    /// Legacy scan-forward (unanchored, no boundaries) exhausted without
    /// finding a plausible next Vec<Entry> header.
    scan_forward_exhausted,
};

pub const WalkResult = struct {
    entry_count: u64 = 0,
    /// Entries with num_txs==0 — the flat TooFewTicks gate's exact counter
    /// (replay_stage.zig:8315 tick_count_seen).
    tick_count_seen: u64 = 0,
    batches: usize = 0,
    tx_ok: u64 = 0,
    tx_parse_fail: u64 = 0,
    ended_offset: usize = 0,
    stop_reason: StopReason = .exhausted,
    /// Set the first time verify_ticks.Verifier (zerohash level, matching
    /// this tree's live build_options.verify_ticks=.zerohash — build.zig
    /// net_opts.addOption(..., "verify_ticks", .zerohash)) reports a
    /// non-.ok verdict. Diagnostic secondary signal; the flat tick_count_seen
    /// gate below is what the live -Dverify_ticks=zerohash binary actually
    /// enforces pre-freeze.
    zerohash_verdict: verify_ticks.Verdict = .ok,
};

/// EXPECTED_TICKS_PER_SLOT flat gate constant, replay_stage.zig:9483 — a
/// literal 64, NOT `(slot-parent_slot)*ticks_per_slot`; see that site's
/// FALSE-POSITIVE-SAFETY comment for why the flat form is a safe subset of
/// the canonical (.full-level) check. Preserved verbatim.
pub const EXPECTED_TICKS_PER_SLOT: u64 = 64;

pub fn walkEntries(data: []const u8, boundaries: []const usize, hashes_per_tick: u64, parent_slot: u64, slot_val: u64) WalkResult {
    var r = WalkResult{};
    var offset: usize = 0;

    var vt = verify_ticks.Verifier.init(.zerohash, hashes_per_tick, parent_slot, slot_val, EXPECTED_TICKS_PER_SLOT);

    var anchored = boundaries.len > 0;
    var comp_bi: usize = 0;
    var cur_comp_end: usize = if (anchored) boundaries[0] else data.len;

    batch_loop: while (offset + 8 <= data.len) {
        var comp_end: usize = if (anchored) cur_comp_end else data.len;
        if (anchored and offset + 8 > comp_end) {
            offset = cur_comp_end;
            comp_bi += 1;
            if (comp_bi < boundaries.len) {
                cur_comp_end = boundaries[comp_bi];
                comp_end = cur_comp_end;
                if (offset + 8 > comp_end) continue;
            } else {
                if (offset + 8 > data.len) break;
                anchored = false;
                comp_end = data.len;
            }
        }

        const prefix_val = std.mem.readInt(u64, data[offset..][0..8], .little);

        if (anchored and (prefix_val == 0 or prefix_val > 1_000_000)) {
            var scan_o: usize = offset + 1;
            var scan_found = false;
            while (scan_o + 56 <= cur_comp_end) : (scan_o += 1) {
                const pc = std.mem.readInt(u64, data[scan_o..][0..8], .little);
                const ph = std.mem.readInt(u64, data[scan_o + 8 ..][0..8], .little);
                const pt = std.mem.readInt(u64, data[scan_o + 48 ..][0..8], .little);
                if (pc > 0 and pc < 10000 and ph > 0 and ph < 5_000_000 and pt <= 10_000) {
                    offset = scan_o;
                    scan_found = true;
                    break;
                }
            }
            if (!scan_found) offset = cur_comp_end;
            continue :batch_loop;
        }

        if (prefix_val > 1_000_000) {
            if (anchored) continue :batch_loop;
            if (boundaries.len > 0) {
                var jumped = false;
                for (boundaries) |b| {
                    if (b > offset) {
                        offset = b;
                        jumped = true;
                        break;
                    }
                }
                if (jumped) continue;
            }
            r.stop_reason = .bad_count_prefix;
            break;
        }

        if (prefix_val == 0) {
            if (anchored) continue :batch_loop;
            if (boundaries.len > 0) {
                var jumped = false;
                for (boundaries) |b| {
                    if (b > offset) {
                        offset = b;
                        jumped = true;
                        break;
                    }
                }
                if (jumped) continue;
                r.stop_reason = .exhausted;
                break;
            }
            var found = false;
            var scan_offset = offset + 1;
            while (scan_offset + 56 <= data.len) : (scan_offset += 1) {
                const probe_count = std.mem.readInt(u64, data[scan_offset..][0..8], .little);
                const probe_hashes = std.mem.readInt(u64, data[scan_offset + 8 ..][0..8], .little);
                const probe_txs = std.mem.readInt(u64, data[scan_offset + 48 ..][0..8], .little);
                if (probe_count > 0 and probe_count < 10000 and
                    probe_hashes > 0 and probe_hashes < 5_000_000 and
                    probe_txs <= 10_000)
                {
                    offset = scan_offset;
                    found = true;
                    break;
                }
            }
            if (found) continue;
            r.stop_reason = .scan_forward_exhausted;
            break;
        }

        if (!anchored and offset + 16 <= data.len) {
            const peek_num_hashes = std.mem.readInt(u64, data[offset + 8 ..][0..8], .little);
            if (peek_num_hashes == 0 or peek_num_hashes > 5_000_000) {
                if (offset > 0) {
                    r.stop_reason = .bad_first_num_hashes_peek;
                    break;
                }
            }
        }

        if (!anchored and offset + 56 <= data.len) {
            const peek_num_txs = std.mem.readInt(u64, data[offset + 48 ..][0..8], .little);
            if (peek_num_txs > 10_000) {
                r.stop_reason = .bad_first_num_txs_peek;
                break;
            }
        }

        offset += 8;
        r.batches += 1;
        const batch_max: usize = @intCast(prefix_val);
        var batch_entry_count: usize = 0;

        while (offset + 48 <= comp_end and batch_entry_count < batch_max) {
            batch_entry_count += 1;
            r.entry_count += 1;

            const num_hashes = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;

            if (num_hashes > 5_000_000) {
                if (anchored) continue :batch_loop;
                r.stop_reason = .suspicious_num_hashes;
                break :batch_loop;
            }

            offset += 32; // entry hash — PoH chain verify deferred to bank.freeze() live; N/A offline

            const num_txs = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;

            if (num_txs > 10_000) {
                if (anchored) continue :batch_loop;
                r.stop_reason = .corrupt_num_txs;
                break :batch_loop;
            }

            if (num_txs == 0) r.tick_count_seen += 1;

            const vt_verdict = vt.onEntry(num_hashes, num_txs == 0);
            if (vt_verdict.isDead() and r.zerohash_verdict == .ok) r.zerohash_verdict = vt_verdict;

            var tx_i: u64 = 0;
            while (tx_i < num_txs) : (tx_i += 1) {
                if (offset >= comp_end) break;
                const tx_start = offset;
                const tx_size = measureTransaction(data, tx_start) catch {
                    r.tx_parse_fail += 1;
                    break;
                };
                if (tx_size == 0 or tx_start + tx_size > comp_end) {
                    r.tx_parse_fail += 1;
                    break;
                }
                offset = tx_start + tx_size;
                r.tx_ok += 1;
            }
        }
    }

    r.ended_offset = offset;
    return r;
}

// ═══════════════════════════════════════════════════════════════════════════
// Top-level verdict
// ═══════════════════════════════════════════════════════════════════════════

pub const TickGateVerdict = enum {
    /// Neither the flat TooFewTicks gate nor the diagnostic zerohash Verifier
    /// fired — the live binary would have proceeded to bank.freeze().
    would_pass,
    /// replay_stage.zig:9483-9495's flat `tick_count_seen < 64` gate fires —
    /// this is what the LIVE binary (built -Dverify_ticks=zerohash, this
    /// tree's build.zig default) actually enforces pre-freeze.
    would_refuse_too_few_ticks,
    /// The canonical verify_ticks zerohash-level check fired (a tick with
    /// num_hashes==0 while hashing is enabled) — would ALSO refuse under any
    /// verify_ticks level >= zerohash.
    would_refuse_zerohash_tick,
};

pub const ReplayVerdict = struct {
    format: Format,
    slot: u64,
    assembled: bool,
    assemble_error_name: ?[]const u8 = null,
    data_len: usize,
    boundaries_used: usize,
    walk: WalkResult,
    tick_gate: TickGateVerdict,
    /// VSD1-path only (0 for raw_entry_buffer — that format carries no
    /// per-shred provenance at all, which is exactly the forensic gap
    /// incident-422359406's postmortem called out: "our corrupted raw shred
    /// set was never preserved, only the post-assembly buffer"). Count of
    /// data shreds that entered assembly via the FEC-completion pull-in path
    /// (SlotAssembly.recovered — shred_assembler.zig:97-110) — i.e. were
    /// Reed-Solomon-reconstructed rather than received directly.
    shreds_recovered: usize = 0,
    shreds_total: usize = 0,

    /// Render to an owned string (caller frees). Zig 0.15's std.io has no
    /// stdout-writer convenience left (see stdoutWrite() below for the raw
    /// std.fs.File{.handle=1} pattern this tree's other CLI tools use), so
    /// this builds the report in memory rather than taking a generic writer.
    pub fn render(self: ReplayVerdict, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);
        try w.print("=== shred-replay verdict ===\n", .{});
        try w.print("format:              {s}\n", .{@tagName(self.format)});
        try w.print("slot:                {d}\n", .{self.slot});
        try w.print("assembled:           {}\n", .{self.assembled});
        if (self.assemble_error_name) |e| try w.print("assemble_error:      {s}\n", .{e});
        try w.print("data_len:            {d}\n", .{self.data_len});
        try w.print("boundaries_used:     {d} (DATA_COMPLETE-derived component count)\n", .{self.boundaries_used});
        if (self.format == .vsd1) {
            try w.print("shreds_recovered:    {d} / {d} (FEC-reconstructed data shreds; SlotAssembly.recovered provenance)\n", .{ self.shreds_recovered, self.shreds_total });
        }
        try w.print("entries_seen:        {d}\n", .{self.walk.entry_count});
        try w.print("ticks_seen:          {d} (of expected {d})\n", .{ self.walk.tick_count_seen, EXPECTED_TICKS_PER_SLOT });
        try w.print("batches_parsed:      {d}\n", .{self.walk.batches});
        try w.print("tx_ok:               {d}\n", .{self.walk.tx_ok});
        try w.print("tx_parse_fail:       {d}\n", .{self.walk.tx_parse_fail});
        try w.print("parse_ended_offset:  {d} / {d}\n", .{ self.walk.ended_offset, self.data_len });
        try w.print("stop_reason:         {s}\n", .{@tagName(self.walk.stop_reason)});
        try w.print("zerohash_verdict:    {s}\n", .{@tagName(self.walk.zerohash_verdict)});
        try w.print("TICK-GATE VERDICT:   {s}\n", .{@tagName(self.tick_gate)});
        return buf.toOwnedSlice(allocator);
    }
};

fn stdoutWrite(bytes: []const u8) !void {
    const f = std.fs.File{ .handle = 1 };
    try f.writeAll(bytes);
}

pub fn replayVsd1(allocator: std.mem.Allocator, file: Vsd1File, hashes_per_tick: u64) ReplayVerdict {
    // parent_slot: derived from the FIRST record's Shred.parentOffset (wire
    // truth, not an assumption) when available.
    var parent_slot: u64 = if (file.slot > 0) file.slot - 1 else 0;
    if (file.records.len > 0) {
        if (shred_pub.parseShred(file.records[0].wire)) |s| {
            parent_slot = file.slot -| s.parentOffset();
        } else |_| {}
    }

    const outcome = assembleFromShreds(allocator, file.slot, file.records) catch |e| {
        return .{
            .format = .vsd1,
            .slot = file.slot,
            .assembled = false,
            .assemble_error_name = @errorName(e),
            .data_len = 0,
            .boundaries_used = 0,
            .walk = .{},
            .tick_gate = .would_pass,
        };
    };

    const walk = walkEntries(outcome.data, outcome.boundaries, hashes_per_tick, parent_slot, file.slot);
    const gate: TickGateVerdict = if (walk.tick_count_seen < EXPECTED_TICKS_PER_SLOT)
        .would_refuse_too_few_ticks
    else if (walk.zerohash_verdict != .ok)
        .would_refuse_zerohash_tick
    else
        .would_pass;

    const data_len = outcome.data.len;
    const boundaries_used = outcome.boundaries.len;
    // The verdict is a summary (counts only) — free the reconstructed buffer
    // + boundaries here rather than leaking them on the caller (matches
    // replayRawEntryBuffer, which never allocates in the first place since
    // its input is already the caller-owned buffer).
    allocator.free(outcome.data);
    allocator.free(outcome.boundaries);

    return .{
        .format = .vsd1,
        .slot = file.slot,
        .assembled = true,
        .data_len = data_len,
        .boundaries_used = boundaries_used,
        .walk = walk,
        .tick_gate = gate,
        .shreds_recovered = outcome.shreds_recovered_provenance,
        .shreds_total = file.records.len,
    };
}

pub fn replayRawEntryBuffer(data: []const u8, slot_val: u64, parent_slot: u64, hashes_per_tick: u64) ReplayVerdict {
    const walk = walkEntries(data, &.{}, hashes_per_tick, parent_slot, slot_val);
    const gate: TickGateVerdict = if (walk.tick_count_seen < EXPECTED_TICKS_PER_SLOT)
        .would_refuse_too_few_ticks
    else if (walk.zerohash_verdict != .ok)
        .would_refuse_zerohash_tick
    else
        .would_pass;

    return .{
        .format = .raw_entry_buffer,
        .slot = slot_val,
        .assembled = true, // N/A — already-assembled buffer, no shred-assembly stage to run
        .data_len = data.len,
        .boundaries_used = 0,
        .walk = walk,
        .tick_gate = gate,
    };
}

/// Best-effort slot extraction from a `vex_slot_<N>_fail.bin` / `vex_slot_<N>_shreds.bin` filename.
pub fn slotFromFilename(path: []const u8) ?u64 {
    const base = std.fs.path.basename(path);
    const prefix = "vex_slot_";
    if (!std.mem.startsWith(u8, base, prefix)) return null;
    const rest = base[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, '_') orelse return null;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════════

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // argv[0]

    var path: ?[]const u8 = null;
    var slot_override: ?u64 = null;
    var hashes_per_tick: u64 = 0;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--slot")) {
            const v = args.next() orelse {
                std.debug.print("--slot requires a value\n", .{});
                std.process.exit(2);
            };
            slot_override = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, a, "--hashes-per-tick")) {
            const v = args.next() orelse {
                std.debug.print("--hashes-per-tick requires a value\n", .{});
                std.process.exit(2);
            };
            hashes_per_tick = try std.fmt.parseInt(u64, v, 10);
        } else if (path == null) {
            path = a;
        }
    }

    const file_path = path orelse {
        std.debug.print(
            \\usage: shred-replay <dump-file> [--slot N] [--hashes-per-tick N]
            \\
            \\  <dump-file>  a VSD1 shred dump (/tmp/vex_slot_<N>_shreds.bin) OR a raw
            \\               assembled-entry-buffer dump (/tmp/vex_slot_<N>_fail.bin).
            \\  --slot       required for raw-entry-buffer input when the filename
            \\               doesn't encode `vex_slot_<N>_...`.
            \\
        , .{});
        std.process.exit(2);
    };

    const bytes = try std.fs.cwd().readFileAlloc(allocator, file_path, 512 * 1024 * 1024);
    defer allocator.free(bytes);

    const fmt = detectFormat(bytes);

    switch (fmt) {
        .vsd1 => {
            const parsed = try parseVsd1(allocator, bytes);
            defer allocator.free(parsed.captured_boundaries);
            defer allocator.free(parsed.records);
            std.debug.print("[shred-replay] VSD1 dump: slot={d} records={d} captured_boundaries={d}\n", .{ parsed.slot, parsed.records.len, parsed.captured_boundaries.len });
            const verdict = replayVsd1(allocator, parsed, hashes_per_tick);
            const rendered = try verdict.render(allocator);
            defer allocator.free(rendered);
            try stdoutWrite(rendered);
        },
        .raw_entry_buffer => {
            const slot_val = slot_override orelse slotFromFilename(file_path) orelse {
                std.debug.print("[shred-replay] raw entry-buffer format (no VSD1 magic) and no slot given — pass --slot N\n", .{});
                std.process.exit(2);
            };
            const parent_slot = slot_val -| 1;
            std.debug.print("[shred-replay] raw entry-buffer dump: slot={d} (parent assumed {d}) len={d}\n", .{ slot_val, parent_slot, bytes.len });
            const verdict = replayRawEntryBuffer(bytes, slot_val, parent_slot, hashes_per_tick);
            const rendered = try verdict.render(allocator);
            defer allocator.free(rendered);
            try stdoutWrite(rendered);
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

fn appendU64(buf: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, v: u64) !void {
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u64, &tmp, v, .little);
    try buf.appendSlice(a, &tmp);
}

/// Build a synthetic raw entry-buffer: `n_ticks` tick-only entries
/// (num_hashes=100, num_txs=0), as ONE Vec<Entry> batch (matches the
/// no-boundaries / unanchored code path fail.bin exercises).
fn buildTickOnlyBuffer(a: std.mem.Allocator, n_ticks: u64) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(a);
    try appendU64(&buf, a, n_ticks); // Vec<Entry> count
    var i: u64 = 0;
    while (i < n_ticks) : (i += 1) {
        try appendU64(&buf, a, 100); // num_hashes
        try buf.appendSlice(a, &([_]u8{0xAB} ** 32)); // hash
        try appendU64(&buf, a, 0); // num_txs
    }
    return buf.toOwnedSlice(a);
}

/// Build ONE valid, `parseShred`-parseable data-shred wire payload (legacy
/// variant 0xA5 — same discriminator `buildBoundaryTestShred` in
/// shred_assembler.zig's own KATs uses — but, unlike that helper, this ALSO
/// fills in the real ShredCommonHeader fields (slot/index/version/fec_set_index/
/// parent_offset at their true wire offsets per shred_parse.zig
/// ShredCommonHeader.fromBytes:75-94) so it survives the REAL `parseShred` +
/// `ShredAssembler.insert` production path, not just direct SlotAssembly
/// manipulation. `content` is the shred's post-header entry-stream payload
/// (may be empty — a "spacer" shred that only occupies an index slot).
fn buildValidTestShred(buf: []u8, slot_val: u64, index: u32, version: u16, fec_set_index: u32, parent_offset: u16, flags: u8, content: []const u8) []const u8 {
    @memset(buf, 0);
    buf[64] = 0xA5; // legacy data variant (is_data=true, non-merkle)
    std.mem.writeInt(u64, buf[65..73], slot_val, .little);
    std.mem.writeInt(u32, buf[73..77], index, .little);
    std.mem.writeInt(u16, buf[77..79], version, .little);
    std.mem.writeInt(u32, buf[79..83], fec_set_index, .little);
    std.mem.writeInt(u16, buf[83..85], parent_offset, .little);
    buf[85] = flags;
    const total_len = 88 + content.len;
    std.mem.writeInt(u16, buf[86..88], @intCast(total_len), .little);
    @memcpy(buf[88..total_len], content);
    return buf[0..total_len];
}

test "VSD1 path end-to-end: real ShredAssembler.insert + parseShred + getAssembledDataWithBoundaries, then walkEntries" {
    // Exercises the tool's HEADLINE capability (the VSD1/shred-assembly path),
    // not just the raw-fail.bin path the incident-422359406 KAT covers — that
    // KAT structurally can't touch assembleFromShreds at all (fail.bin IS
    // already an assembled buffer). 32-shred FEC-set-boundary-complete slot
    // (index 31 carries LAST_IN_SLOT|DATA_COMPLETE = 0xC0, ON the (idx+1)%32==0
    // boundary the pre-existing FEC-BOUNDARY-GUARD requires — see
    // shred_assembler.zig getAssembledDataWithBoundaries/insert — or is_complete
    // never latches and this test would correctly fail loud). Shred 0 alone
    // carries the real content (a valid 2-tick Vec<Entry> stream); shreds
    // 1..31 are zero-content index-slot spacers.
    const a = testing.allocator;
    const slot_val: u64 = 900050;

    const content = try buildTickOnlyBuffer(a, 2); // 8 + 2*48 = 104 bytes
    defer a.free(content);

    var records = std.ArrayListUnmanaged(RawShredRecord){};
    defer {
        for (records.items) |r| a.free(r.wire);
        records.deinit(a);
    }
    var idx: u32 = 0;
    // shred 31 (the DATA_COMPLETE|LAST_IN_SLOT carrier) needs >0 content
    // bytes for getAssembledDataWithBoundaries to register a boundary at all
    // (shred_assembler.zig:1846 `if (raw_size > HDR_SZ)` gates the WHOLE
    // per-shred contribution, boundary-append included) — real leader-produced
    // last shreds always carry at least their tail padding, so this is a
    // realistic single zero-padding byte, not a special-case for the test.
    const tail_padding = [_]u8{0};
    while (idx < 32) : (idx += 1) {
        var buf: [300]u8 = undefined;
        const is_last = (idx == 31);
        const flags: u8 = if (is_last) 0xC0 else 0x00;
        const payload_content: []const u8 = if (idx == 0) content else if (is_last) &tail_padding else &.{};
        const wire = buildValidTestShred(&buf, slot_val, idx, 0, 0, 1, flags, payload_content);
        try records.append(a, .{ .index = idx, .recovered = false, .wire = try a.dupe(u8, wire) });
    }

    const outcome = try assembleFromShreds(a, slot_val, records.items);
    defer a.free(outcome.data);
    defer a.free(outcome.boundaries);

    try testing.expectEqual(@as(usize, 32), outcome.shreds_inserted);
    try testing.expectEqual(@as(usize, 105), outcome.data.len); // 104 content + 1 tail-padding byte
    try testing.expectEqual(@as(usize, 1), outcome.boundaries.len);
    try testing.expectEqual(@as(usize, 105), outcome.boundaries[0]); // DATA_COMPLETE at the very end

    const verdict = replayVsd1(a, .{ .slot = slot_val, .captured_boundaries = &.{}, .records = records.items }, 0);
    try testing.expect(verdict.assembled);
    try testing.expectEqual(@as(u64, 2), verdict.walk.entry_count);
    try testing.expectEqual(@as(u64, 2), verdict.walk.tick_count_seen);
    try testing.expectEqual(TickGateVerdict.would_refuse_too_few_ticks, verdict.tick_gate); // 2 << 64, expected for this tiny synthetic block
}

test "walkEntries: complete 64-tick block passes the flat gate" {
    const a = testing.allocator;
    const buf = try buildTickOnlyBuffer(a, 64);
    defer a.free(buf);

    const verdict = replayRawEntryBuffer(buf, 500, 499, 0);
    try testing.expectEqual(@as(u64, 64), verdict.walk.tick_count_seen);
    try testing.expectEqual(@as(u64, 64), verdict.walk.entry_count);
    try testing.expectEqual(TickGateVerdict.would_pass, verdict.tick_gate);
}

test "walkEntries: truncated block (39 ticks) fires the flat TooFewTicks gate" {
    const a = testing.allocator;
    const buf = try buildTickOnlyBuffer(a, 39);
    defer a.free(buf);

    const verdict = replayRawEntryBuffer(buf, 500, 499, 0);
    try testing.expectEqual(@as(u64, 39), verdict.walk.tick_count_seen);
    try testing.expectEqual(TickGateVerdict.would_refuse_too_few_ticks, verdict.tick_gate);
}

test "slotFromFilename parses vex_slot_<N>_fail.bin and _shreds.bin" {
    try testing.expectEqual(@as(?u64, 422359406), slotFromFilename("/tmp/vex_slot_422359406_fail.bin"));
    try testing.expectEqual(@as(?u64, 422359406), slotFromFilename("/home/x/vex_slot_422359406_shreds.bin"));
    try testing.expectEqual(@as(?u64, null), slotFromFilename("/tmp/not_a_vex_dump.bin"));
}

test "detectFormat: VSD1 magic vs raw buffer" {
    try testing.expectEqual(Format.vsd1, detectFormat("VSD1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
    const a = testing.allocator;
    const raw = try buildTickOnlyBuffer(a, 1);
    defer a.free(raw);
    try testing.expectEqual(Format.raw_entry_buffer, detectFormat(raw));
}

test "parseVsd1 round-trips a hand-built dump" {
    const a = testing.allocator;
    var buf2 = std.ArrayListUnmanaged(u8){};
    defer buf2.deinit(a);
    try buf2.appendSlice(a, "VSD1");
    try buf2.append(a, 1);
    try appendU64(&buf2, a, 12345); // slot
    var u32buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &u32buf, 1, .little); // num_boundaries
    try buf2.appendSlice(a, &u32buf);
    try appendU64(&buf2, a, 1203); // boundary[0]
    std.mem.writeInt(u32, &u32buf, 1, .little); // num_records
    try buf2.appendSlice(a, &u32buf);
    // record 0: index=5, recovered=1, len=3, payload={1,2,3}
    std.mem.writeInt(u32, &u32buf, 5, .little);
    try buf2.appendSlice(a, &u32buf);
    try buf2.append(a, 1);
    var u16buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &u16buf, 3, .little);
    try buf2.appendSlice(a, &u16buf);
    try buf2.appendSlice(a, &[_]u8{ 1, 2, 3 });

    const parsed = try parseVsd1(a, buf2.items);
    defer a.free(parsed.captured_boundaries);
    defer a.free(parsed.records);

    try testing.expectEqual(@as(u64, 12345), parsed.slot);
    try testing.expectEqual(@as(usize, 1), parsed.captured_boundaries.len);
    try testing.expectEqual(@as(u64, 1203), parsed.captured_boundaries[0]);
    try testing.expectEqual(@as(usize, 1), parsed.records.len);
    try testing.expectEqual(@as(u32, 5), parsed.records[0].index);
    try testing.expect(parsed.records[0].recovered);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, parsed.records[0].wire);
}

// ── KAT: real incident-422359406 capture (forensics/incident-422359406-tickgate-stall) ──
//
// Regression fixture too big to commit (197076B); referenced by forensics path +
// md5 and SKIPPED (not failed) if absent from this machine. When present, its
// md5 is verified first (a mismatched fixture would silently validate the wrong
// bytes) — see incident memory
// incident-422359406-fec-datacomplete-truncation-2026-07-16.md for provenance:
// "OUR corrupted copy... (197076B md5 993bb497f00598ea345080f6dd2c0847) — fixed
// assembler must NOT produce/accept this."
const FAIL_BIN_PATH = "/home/davidb/forensics/incident-422359406-tickgate-stall/vex_slot_422359406_fail.bin";
const FAIL_BIN_MD5 = "993bb497f00598ea345080f6dd2c0847";

fn hexDigest(digest: [std.crypto.hash.Md5.digest_length]u8) [32]u8 {
    const hex_chars = "0123456789abcdef";
    var out: [32]u8 = undefined;
    for (digest, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0xF];
    }
    return out;
}

test "KAT incident-422359406: real fail.bin reproduces the live TooFewTicks refusal" {
    const a = testing.allocator;
    const f = std.fs.cwd().openFile(FAIL_BIN_PATH, .{}) catch |e| {
        if (e == error.FileNotFound) return error.SkipZigTest;
        return e;
    };
    defer f.close();
    const bytes = try f.readToEndAlloc(a, 8 * 1024 * 1024);
    defer a.free(bytes);

    var digest: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(bytes, &digest, .{});
    const got_hex = hexDigest(digest);
    if (!std.mem.eql(u8, &got_hex, FAIL_BIN_MD5)) {
        std.debug.print("[KAT] fail.bin md5 mismatch: got {s} want {s} — fixture drifted, skipping (not failing) this KAT\n", .{ got_hex, FAIL_BIN_MD5 });
        return error.SkipZigTest;
    }

    try testing.expectEqual(Format.raw_entry_buffer, detectFormat(bytes));

    const verdict = replayRawEntryBuffer(bytes, 422359406, 422359405, 0);
    // Proof-of-execution + verbatim verdict in the KAT's own test log (not
    // just a boolean pass) — md5 verified above, so this really is the real
    // incident capture, not a skip.
    std.debug.print("[KAT incident-422359406] md5-verified real fail.bin ran: entries={d} ticks={d} stop_reason={s} gate={s}\n", .{
        verdict.walk.entry_count, verdict.walk.tick_count_seen, @tagName(verdict.walk.stop_reason), @tagName(verdict.tick_gate),
    });

    // RCA (CANONICAL-COMPARISON.md, incident-422359406-tickgate-stall):
    // "OUR copy assembled truncated: parse aborted offset 165400/197076 →
    // 448 entries/39 ticks vs canonical 546/64 → BadBlockTickValidity".
    // This loader must reproduce the SAME class of failure: the live
    // -Dverify_ticks=zerohash binary's flat TooFewTicks gate refuses.
    try testing.expectEqual(TickGateVerdict.would_refuse_too_few_ticks, verdict.tick_gate);
    try testing.expect(verdict.walk.tick_count_seen < EXPECTED_TICKS_PER_SLOT);
}
