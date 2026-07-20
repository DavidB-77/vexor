//! Parallel Snapshot Loading
//!
//! Optimizes snapshot loading by:
//! 1. Pre-scanning the file list
//! 2. Threaded mmap + parse (avoids the copy path; see mmapAndIndex)
//! 3. Parallel AppendVec parsing (CPU-bound)
//! 4. Batched account storage
//!
//! This can provide 4-8x speedup on multi-core systems.

const std = @import("std");
const snapshot_manifest = @import("snapshot_manifest.zig");
const fs = std.fs;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Allocator = std.mem.Allocator;
const core = @import("core");
const accounts = @import("accounts.zig");

/// Parsed account ready for storage
pub const ParsedAccount = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
    slot: u64,
};

/// Result from parsing a single AppendVec file
pub const FileParseResult = struct {
    accounts: []ParsedAccount,
    lamports_total: u64,

    pub fn deinit(self: FileParseResult, allocator: Allocator) void {
        for (self.accounts) |acc| {
            if (acc.data.len > 0) {
                allocator.free(@constCast(acc.data));
            }
        }
        allocator.free(self.accounts);
    }
};

/// Result from mmap+index pass (no data copy)
pub const MmapIndexResult = struct {
    store_id: u32,
    accounts_indexed: u64,
    lamports_total: u64,
    mmap_ptr: [*]align(4096) u8,
    mmap_size: usize,
};

/// carrier-414371294 (2026-06-10): why a record walk stopped.
pub const WalkReason = enum {
    /// clean end-of-data marker (all-zero pubkey + 0 lamports + 0 data_len)
    terminator,
    /// reached the limit at a record boundary (or trailing zero padding < 136 B)
    limit,
    /// a record's header or data crosses the limit — truncation suspect
    straddle,
    /// implausible data_len (> 10 MiB) — garbage / not a record
    garbage,
};

pub const WalkResult = struct {
    /// Offset just past the last fully-parsed record (8-aligned).
    /// May exceed `limit` when a zero-lamport record's data crosses it
    /// (mirrors the index loop's unconditional dead-account skip).
    end_offset: usize,
    /// Records with lamports > 0 (the ones the index loop would insert).
    live_records: u64,
    reason: WalkReason,
};

/// Walk Agave-format appendvec records in data[start..limit] WITHOUT
/// indexing. Validation mirrors mmapAndIndex's scan loop exactly. Used by the
/// carrier-414371294 length-resolution pass to decide whether a manifest
/// length that is shorter than the physical file truncates real records.
pub fn walkRecords(data: []const u8, start: usize, limit: usize) WalkResult {
    const STORED_META_SIZE: usize = 48;
    const ACCOUNT_META_SIZE: usize = 56;
    const HASH_SIZE: usize = 32;
    const MIN_ACCOUNT_SIZE: usize = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE;
    const MAX_ACCOUNT_DATA_LEN: u64 = 10 * 1024 * 1024;

    var offset: usize = start;
    var live: u64 = 0;
    while (true) {
        if (offset + MIN_ACCOUNT_SIZE > limit) {
            // Clean end if we're at/past the limit or the remainder is zero
            // padding; otherwise a header straddles the limit.
            const clean = offset >= limit or std.mem.allEqual(u8, data[offset..limit], 0);
            return .{ .end_offset = offset, .live_records = live, .reason = if (clean) .limit else .straddle };
        }
        const data_len = std.mem.readInt(u64, data[offset + 8 ..][0..8], .little);
        if (data_len > MAX_ACCOUNT_DATA_LEN)
            return .{ .end_offset = offset, .live_records = live, .reason = .garbage };

        const pubkey = data[offset + 16 ..][0..32];
        const lamports = std.mem.readInt(u64, data[offset + STORED_META_SIZE ..][0..8], .little);
        if (lamports == 0 and data_len == 0 and std.mem.allEqual(u8, pubkey, 0))
            return .{ .end_offset = offset, .live_records = live, .reason = .terminator };

        const record_len = MIN_ACCOUNT_SIZE + @as(usize, @intCast(data_len));
        if (lamports > 0) {
            if (offset + record_len > limit)
                return .{ .end_offset = offset, .live_records = live, .reason = .straddle };
            live += 1;
        }
        // NOTE: zero-lamport (dead) records advance unconditionally, exactly
        // like the index loop's dead-account skip — their data may cross the
        // limit without it being a truncation signal.
        const pad = (8 - (record_len % 8)) & 7;
        offset += record_len + pad;
    }
}

/// Configuration for parallel loading
pub const ParallelConfig = struct {
    /// Number of worker threads (default: CPU count - 1)
    num_threads: usize = 0,
    /// Batch size for account storage
    batch_size: usize = 1000,
    /// Enable verbose logging
    verbose: bool = false,
    /// Number of storage worker threads (default: same as num_threads)
    storage_threads: usize = 0,
};

/// Context for batch storage worker threads
pub const BatchStoreContext = struct {
    /// Slice of results to process (subset for this worker)
    results: []?FileParseResult,
    /// Corresponding error flags
    errors: []?anyerror,
    /// Start index in the results array
    start_idx: usize,
    /// End index (exclusive) in the results array
    end_idx: usize,
    /// AccountsDb reference (type-erased)
    accounts_db_ptr: *anyopaque,
    /// Atomic counters for aggregation
    accounts_loaded: *std.atomic.Value(u64),
    lamports_total: *std.atomic.Value(u64),
    error_count: *std.atomic.Value(u64),
    appendvec_writes: *std.atomic.Value(u64),
    /// Allocator for freeing parsed data
    allocator: Allocator,
};

/// Parallel snapshot loader
pub const ParallelSnapshotLoader = struct {
    const Self = @This();

    allocator: Allocator,
    config: ParallelConfig,

    // accounts_lt_hash extracted from snapshot manifest (authoritative base LtHash)
    snapshot_lthash: ?[2048]u8 = null,
    snapshot_bank_hash: ?[32]u8 = null,
    snapshot_block_height: ?u64 = null,
    snapshot_capitalization: ?u64 = null,
    /// CONSENSUS-CRITICAL (epoch-979 tip carrier): snapshot-restored fee-rate
    /// governor + signature_count, captured from the manifest. Bootstrap seeds
    /// the root bank's `fee_rate_governor` / `signature_count` from these so the
    /// first per-slot `FeeRateGovernor.newDerived` matches Agave rc.1.
    snapshot_fee_rate_governor: ?snapshot_manifest.FeeRateGovernor = null,
    snapshot_signature_count: ?u64 = null,
    /// task #28: effective PoH cadence from the snapshot bank manifest (testnet 62500/64, NOT the
    /// genesis 12500). Source of truth for the block producer + PoH verifier; defaults are a fallback.
    snapshot_hashes_per_tick: u64 = 62500,
    snapshot_ticks_per_slot: u64 = 64,
    /// verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19): the
    /// manifest's RAW Option<u64> hashes_per_tick, preserved un-defaulted. The
    /// `snapshot_hashes_per_tick` field above collapses None→62500 for the block
    /// producer; the canonical tick-validity check instead needs Agave's
    /// `bank.hashes_per_tick().unwrap_or(0)` semantics (None → 0 → skip hash-count
    /// checks). Bootstrap reads THIS field and applies `orelse 0`.
    snapshot_hashes_per_tick_raw: ?u64 = null,
    /// carrier #13 (2026-06-11): the FULL snapshot's slot = the incremental's
    /// base_slot. Records from stores with slot > this come from the INCREMENTAL
    /// and a zero-lamport one there is a TOMBSTONE that must shadow the full's
    /// alive version (insert it). Zero-lamport records at slot <= this are the
    /// full's own dead accounts (shadow nothing within a point-in-time full) and
    /// are skipped for RSS. null = single full snapshot (no incremental) ⇒ all
    /// zero-lamport skipped, matching Agave's cleaned full. See
    /// snapshot-load hardening (Agave accounts_db.rs:5941/6000, load filter 3614).
    incremental_base_slot: ?u64 = null,
    /// d28pp (2026-05-12): SIMD-0340 chained_block_id from snapshot tail.
    /// Populated when the snapshot file uses block_id=Some(Hash) layout
    /// (Agave v4.0.0-beta.6+). Wired through to root_bank.block_id at
    /// bootstrap so SIMD-0340 detection has a canonical cluster reference
    /// from slot anchor+1 onward.
    snapshot_block_id: ?[32]u8 = null,
    /// last_blockhash (BlockhashQueue.last_hash) of the snapshot slot — last PoH
    /// entry hash, distinct from bank_hash. Wired to root_bank.poh_hash so the
    /// post-snapshot epoch-boundary EpochRewards.parent_blockhash is canonical.
    /// carrier #16 @414812256.
    snapshot_blockhash: ?[32]u8 = null,
    /// Vote-account → stake captured from the snapshot's Stakes.vote_accounts.
    /// Owned here; freed in deinit. Consumed by main.zig to seed Bank's
    /// stake-weighted Clock computation.
    snapshot_vote_stakes: []snapshot_manifest.VoteAccountStake = &[_]snapshot_manifest.VoteAccountStake{},
    /// carrier #16: parallel FROZEN vote account data (same indexing).
    snapshot_vote_frozen: []const []const u8 = &.{},
    /// d16 (2026-05-10): per-epoch frozen vote-account stake tables from the
    /// snapshot's `epoch_stakes` blob (Agave's authoritative source for
    /// SIMD-0001 stake-weighted Clock at any slot in a given epoch). Owned
    /// here; each entry's nested slice + the outer slice are freed in deinit.
    snapshot_epoch_stakes: []const snapshot_manifest.EpochStakesEntry = &[_]snapshot_manifest.EpochStakesEntry{},
    /// F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): the snapshot bank's `hard_forks`
    /// list (was discarded at parse). Owned here; ownership is transferred to
    /// AccountsDb.hard_forks at bootstrap (loader pointer reset to empty) and
    /// freed in AccountsDb.deinit. Drives F2 (bank-hash mixin) + F3
    /// (LastRestartSlot sysvar). DORMANT on post-restart testnet.
    snapshot_hard_forks: []const snapshot_manifest.HardFork = &[_]snapshot_manifest.HardFork{},

    // Stats
    files_processed: std.atomic.Value(u64),
    accounts_parsed: std.atomic.Value(u64),
    bytes_processed: std.atomic.Value(u64),
    blocking_reads: std.atomic.Value(u64),

    // carrier-414371294 (2026-06-10): manifest-length-mismatch counters.
    // A file whose manifest len < stat size with parseable records in the
    // tail indicates a wrong-provenance length (or manifest corruption).
    // accounts_skipped_len_mismatch MUST be 0 on a healthy boot; recovered
    // accounts are indexed but logged LOUDLY per file.
    len_mismatch_files: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    accounts_recovered_len_mismatch: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    accounts_skipped_len_mismatch: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(allocator: Allocator, config: ParallelConfig) Self {
        var actual_config = config;
        if (actual_config.num_threads == 0) {
            // Default to CPU count - 1, minimum 1
            const cpu_count = std.Thread.getCpuCount() catch 4;
            actual_config.num_threads = @max(1, cpu_count -| 1);
        }

        return Self{
            .allocator = allocator,
            .config = actual_config,
            .files_processed = std.atomic.Value(u64).init(0),
            .accounts_parsed = std.atomic.Value(u64).init(0),
            .bytes_processed = std.atomic.Value(u64).init(0),
            .blocking_reads = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Fast single-pass: mmap file → scan accounts → register as Agave store → insert index.
    /// No data copy, no re-serialization. Keeps mmap alive for the life of the process.
    pub fn mmapAndIndex(
        self: *Self,
        file_path: []const u8,
        slot: u64,
        file_sz: ?u64,
        accounts_db: anytype,
    ) !MmapIndexResult {
        var file = try fs.cwd().openFile(file_path, .{});
        defer file.close();

        const stat = try file.stat();
        const stat_size = stat.size;
        var file_size: usize = if (file_sz) |fz|
            @intCast(@min(fz, stat_size))
        else
            @intCast(stat_size);

        // r71-fix-4 (2026-04-28): targeted probe — log file_sz for the file
        // containing the GJHtFqM9 program account (slot=316733740 id=45741).
        // If file_sz < 289424 the parser stops before reaching the program.
        if (slot == 316733740 and std.mem.endsWith(u8, file_path, ".45741")) {
            std.log.debug("[FILE-SZ-PROBE] file=316733740.45741 stat_size={d} manifest_file_sz={?d} effective_size={d} target_offset=289424\n", .{ stat_size, file_sz, file_size });
        }

        if (stat_size == 0) {
            return MmapIndexResult{ .store_id = 0, .accounts_indexed = 0, .lamports_total = 0, .mmap_ptr = undefined, .mmap_size = 0 };
        }

        // mmap with READ+WRITE so we can pass []u8 (not []const u8) to registerAgaveMmap
        const mmap_size: usize = @intCast(stat_size);
        const mapped = try std.posix.mmap(
            null,
            mmap_size,
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        );
        std.posix.madvise(mapped.ptr, mmap_size, 2) catch {}; // MADV_SEQUENTIAL (forward load scan)
        // MADV_HUGEPAGE (14): this mmap stays alive for the validator lifetime and post-load becomes
        // RANDOM-access (account index lookups → store offset). Transparent hugepages cut TLB misses
        // ~512× on the GiB-scale account region for both the sequential load AND the random runtime
        // lookups. Advisory (kernel may ignore), perf-only, ZERO bank_hash impact. (MAP_HUGETLB would
        // EINVAL on a file-backed mmap — MADV_HUGEPAGE is the correct mechanism for THP on file maps.)
        std.posix.madvise(mapped.ptr, mmap_size, 14) catch {}; // MADV_HUGEPAGE

        const data: []u8 = @as([*]u8, @ptrCast(mapped))[0..mmap_size];

        // ── carrier-414371294 (2026-06-10): length resolution — NEVER silently
        // truncate. If the manifest-derived length is shorter than the
        // physical file AND real records sit beyond it, the length is wrong
        // (e.g. a wrong-provenance manifest len; root cause fixed upstream by
        // mergeFileSzMapsByProvenance). Recover a fully-valid tail LOUDLY;
        // refuse (and count) an unparseable one. The proven carrier: full-
        // archive appendvec 414364417.1455839 (131,624 B) parsed with the
        // incremental manifest's post-shrink len 131,488 → the last entry
        // (ClusterHistory PDA 2FC547gL…) silently never indexed.
        if (file_size < mmap_size) {
            const w1 = walkRecords(data, 0, file_size);
            if (w1.reason == .limit or w1.reason == .straddle) {
                const tail_start = @min(w1.end_offset, mmap_size);
                const w2 = walkRecords(data, tail_start, mmap_size);
                const tail_valid = w2.reason == .terminator or w2.reason == .limit;
                if (w2.live_records > 0) {
                    _ = self.len_mismatch_files.fetchAdd(1, .monotonic);
                    if (tail_valid) {
                        file_size = @min(w2.end_offset, mmap_size);
                        _ = self.accounts_recovered_len_mismatch.fetchAdd(w2.live_records, .monotonic);
                        std.log.warn("[SNAPLOAD-LEN-MISMATCH] file={s} manifest_len={?d} stat={d} tail VALID — RECOVERED {d} live account(s), effective_len={d}", .{
                            file_path, file_sz, stat_size, w2.live_records, file_size,
                        });
                    } else {
                        _ = self.accounts_skipped_len_mismatch.fetchAdd(w2.live_records, .monotonic);
                        std.log.err("[SNAPLOAD-LEN-MISMATCH] file={s} manifest_len={?d} stat={d} tail INVALID ({s} at {d}) — {d} live account(s) SKIPPED (DATA LOSS)", .{
                            file_path, file_sz, stat_size, @tagName(w2.reason), w2.end_offset, w2.live_records,
                        });
                    }
                } else if (!std.mem.allEqual(u8, data[tail_start..mmap_size], 0)) {
                    // Non-zero tail with no parseable live records: anomalous
                    // (zero padding is the only expected tail). Loud, but no
                    // account counted — nothing record-shaped was lost.
                    _ = self.len_mismatch_files.fetchAdd(1, .monotonic);
                    std.log.warn("[SNAPLOAD-LEN-MISMATCH] file={s} manifest_len={?d} stat={d} non-zero tail, no live records (reason={s} at {d})", .{
                        file_path, file_sz, stat_size, @tagName(w2.reason), w2.end_offset,
                    });
                }
            }
        }

        if (file_size == 0) {
            std.posix.munmap(mapped);
            return MmapIndexResult{ .store_id = 0, .accounts_indexed = 0, .lamports_total = 0, .mmap_ptr = undefined, .mmap_size = 0 };
        }

        // Register as an Agave-format store (read-only, no copy)
        const store_id = try accounts_db.registerAgaveMmap(data, @intCast(file_size));

        // Scan accounts and insert index entries (no data copy)
        const STORED_META_SIZE: usize = 48;
        const ACCOUNT_META_SIZE: usize = 56;
        const HASH_SIZE: usize = 32;
        const MIN_ACCOUNT_SIZE: usize = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE;
        const MAX_ACCOUNT_DATA_LEN: u64 = 10 * 1024 * 1024;

        var offset: usize = 0;
        var accounts_indexed: u64 = 0;
        var lamports_total: u64 = 0;

        while (offset + MIN_ACCOUNT_SIZE <= file_size) {
            const data_len = std.mem.readInt(u64, data[offset + 8 ..][0..8], .little);
            if (data_len > MAX_ACCOUNT_DATA_LEN) break;

            var pubkey: [32]u8 = undefined;
            @memcpy(&pubkey, data[offset + 16 ..][0..32]);

            const meta_offset = offset + STORED_META_SIZE;
            if (meta_offset + ACCOUNT_META_SIZE + HASH_SIZE > file_size) break;

            const lamports = std.mem.readInt(u64, data[meta_offset..][0..8], .little);

            // End-of-data: all-zero pubkey + zero lamports + zero data
            if (lamports == 0 and data_len == 0 and std.mem.allEqual(u8, &pubkey, 0)) break;

            // carrier #13 (2026-06-11): zero-lamport handling — canonical Agave.
            // A zero-lamport record from the INCREMENTAL (slot > full base_slot)
            // is a TOMBSTONE: the account was CLOSED, and it must shadow the
            // full archive's older ALIVE version for the same pubkey. Insert it
            // (fall through) so HIGHER-SLOT-WINS (accounts_index.zig) makes it the
            // index head and getAccountInSlot returns null for it. A zero-lamport
            // record from the FULL (slot <= base_slot, or single-snapshot load)
            // shadows nothing within a point-in-time full → skip it for RSS
            // (Agave's full is already cleaned; ~half of raw entries are dead).
            if (lamports == 0) {
                const is_incremental_tombstone = if (self.incremental_base_slot) |fb| slot > fb else false;
                if (!is_incremental_tombstone) {
                    const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(data_len));
                    const pad = (8 - (record_len % 8)) & 7;
                    offset += record_len + pad;
                    continue;
                }
            }

            const data_end = meta_offset + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(data_len));
            if (data_end > file_size) break;

            // Insert index entry pointing at this offset in the mmap'd data
            const pk = @as(*const core.Pubkey, @ptrCast(&pubkey));

            // r71-fix-4 (vex-061 diag): probe inserts of known-missing program pubkeys
            // to localize whether the file is loaded + record reached.
            if (pubkey[0] == 0xe3 and pubkey[1] == 0x4d and pubkey[2] == 0x44 and pubkey[3] == 0xa4) {
                std.log.debug("[BOOT-IDX-PROBE] insert GJHtFqM9 file_slot={d} store_id={d} offset={d} lamports={d}\n", .{ slot, store_id, offset, lamports });
            } else if (pubkey[0] == 0x07 and pubkey[1] == 0x61 and pubkey[2] == 0x48 and pubkey[3] == 0x1d and pubkey[31] == 0x00) {
                std.log.debug("[BOOT-IDX-PROBE] insert Vote file_slot={d} store_id={d} offset={d} lamports={d}\n", .{ slot, store_id, offset, lamports });
            } else if (pubkey[0] == 0x8c and pubkey[1] == 0x97 and pubkey[2] == 0x25 and pubkey[3] == 0x8f) {
                std.log.debug("[BOOT-IDX-PROBE] insert ATA file_slot={d} store_id={d} offset={d} lamports={d}\n", .{ slot, store_id, offset, lamports });
            } else if (pubkey[0] == 0x06 and pubkey[1] == 0x5a and pubkey[2] == 0xfb and pubkey[3] == 0x9d) {
                std.log.debug("[BOOT-IDX-PROBE] insert Router file_slot={d} store_id={d} offset={d} lamports={d}\n", .{ slot, store_id, offset, lamports });
            }

            try accounts_db.index.insert(pk, accounts.AccountLocation{
                .store_id = store_id,
                .offset = @intCast(offset),
                .slot = slot,
            });

            accounts_indexed += 1;
            lamports_total +|= lamports;

            const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(data_len));
            const pad = (8 - (record_len % 8)) & 7;
            offset += record_len + pad;
        }

        _ = self.files_processed.fetchAdd(1, .monotonic);
        _ = self.accounts_parsed.fetchAdd(accounts_indexed, .monotonic);
        _ = self.bytes_processed.fetchAdd(@intCast(file_size), .monotonic);

        return MmapIndexResult{
            .store_id = store_id,
            .accounts_indexed = accounts_indexed,
            .lamports_total = lamports_total,
            .mmap_ptr = @alignCast(mapped.ptr),
            .mmap_size = mmap_size,
        };
    }

    /// Parse accounts from a buffer (mmap or blocking-read backed)
    pub fn parseBuffer(self: *Self, buf: []const u8, slot: u64) !FileParseResult {
        // file_size: if file_sz from manifest is available and smaller, use it
        // to avoid reading pre-allocated zero-padding past the valid data.
        // Caller sets buf to buf[0..file_sz] when manifest is available.
        const file_size = buf.len;

        if (file_size == 0) {
            return FileParseResult{
                .accounts = &[_]ParsedAccount{},
                .lamports_total = 0,
            };
        }

        // Parse accounts
        var parsed_accounts = std.ArrayListUnmanaged(ParsedAccount){};
        errdefer {
            for (parsed_accounts.items) |*acc| {
                if (acc.data.len > 0) {
                    self.allocator.free(@constCast(acc.data));
                }
            }
            parsed_accounts.deinit(self.allocator);
        }

        var offset: usize = 0;
        var lamports_total: u64 = 0;

        // Agave AppendVec on-disk record layout (matches snapshot.zig and ripatel's spec):
        //   StoredMeta:  8 (write_version) + 8 (data_len) + 32 (pubkey) = 48 bytes
        //   AccountMeta: 8 (lamports) + 8 (rent_epoch) + 32 (owner) + 1 (executable) + 7 (padding) = 56 bytes
        //   Hash:        32 bytes  ← BETWEEN AccountMeta and data, always present
        //   Data:        data_len bytes
        //   Padding:     to next 8-byte boundary
        // Minimum entry with 0 data = 48 + 56 + 32 = 136 bytes
        const STORED_META_SIZE: usize = 48;
        const ACCOUNT_META_SIZE: usize = 56;
        const HASH_SIZE: usize = 32;
        const MIN_ACCOUNT_SIZE: usize = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE;
        const MAX_ACCOUNT_DATA_LEN: u64 = 10 * 1024 * 1024;

        while (offset + MIN_ACCOUNT_SIZE <= file_size) {
            // Agave AppendVec: write_version is OBSOLETE (always 0 in modern Agave).
            // data_len=0 is valid for wallet accounts with no program data.
            // Do NOT break on write_version=0 + data_len=0 — that skips most accounts!
            const data_len = std.mem.readInt(u64, buf[offset + 8 ..][0..8], .little);
            if (data_len > MAX_ACCOUNT_DATA_LEN) break;

            var pubkey: [32]u8 = undefined;
            @memcpy(&pubkey, buf[offset + 16 ..][0..32]);

            const meta_offset = offset + STORED_META_SIZE;
            if (meta_offset + ACCOUNT_META_SIZE + HASH_SIZE > file_size) break;

            const lamports = std.mem.readInt(u64, buf[meta_offset..][0..8], .little);

            // Detect zero-padded end-of-data: all-zero pubkey + zero lamports + zero data
            // Real accounts always have non-zero pubkey OR non-zero lamports
            if (lamports == 0 and data_len == 0 and std.mem.allEqual(u8, &pubkey, 0)) break;

            // carrier #13 (2026-06-11): selective zero-lamport handling, MUST
            // match mmapAndIndex. Incremental tombstones (slot > full base_slot)
            // are INSERTED to shadow the full's alive version; full-snapshot
            // zero-lamport records shadow nothing and are skipped for RSS.
            if (lamports == 0) {
                const is_incremental_tombstone = if (self.incremental_base_slot) |fb| slot > fb else false;
                if (!is_incremental_tombstone) {
                    const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(data_len));
                    const pad = (8 - (record_len % 8)) & 7;
                    offset += record_len + pad;
                    continue;
                }
            }

            const rent_epoch = std.mem.readInt(u64, buf[meta_offset + 8 ..][0..8], .little);

            var owner: [32]u8 = undefined;
            @memcpy(&owner, buf[meta_offset + 16 ..][0..32]);

            const executable = buf[meta_offset + 48] != 0;

            // Hash(32) sits between AccountMeta and data — skip it to reach data
            const data_offset = meta_offset + ACCOUNT_META_SIZE + HASH_SIZE;
            const data_end = data_offset + @as(usize, @intCast(data_len));

            if (data_end > file_size) break;

            // Copy data
            const data = if (data_len > 0) blk: {
                const d = try self.allocator.alloc(u8, @intCast(data_len));
                @memcpy(d, buf[data_offset..data_end]);
                break :blk d;
            } else &[_]u8{};

            try parsed_accounts.append(self.allocator, ParsedAccount{
                .pubkey = pubkey,
                .lamports = lamports,
                .owner = owner,
                .executable = executable,
                .rent_epoch = rent_epoch,
                .data = data,
                .slot = slot,
            });

            lamports_total +|= lamports;

            // Advance to next account — record size includes the hash field
            const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(data_len));
            const pad = (8 - (record_len % 8)) & 7;
            offset += record_len + pad;
        }

        return FileParseResult{
            .accounts = try parsed_accounts.toOwnedSlice(self.allocator),
            .lamports_total = lamports_total,
        };
    }

    /// Parse a single AppendVec file (thread-safe, no shared state)
    /// mmap-backed with a blocking-read fallback (see parseAppendVecWithSz)
    pub fn parseAppendVec(self: *Self, file_path: []const u8, slot: u64) !FileParseResult {
        return self.parseAppendVecWithSz(file_path, slot, null);
    }

    pub fn parseAppendVecWithSz(self: *Self, file_path: []const u8, slot: u64, file_sz: ?u64) !FileParseResult {
        var file = try fs.cwd().openFile(file_path, .{});
        defer file.close();

        const stat = try file.stat();
        const stat_size = stat.size;
        const file_size: usize = if (file_sz) |fz|
            @intCast(@min(fz, stat_size))
        else
            @intCast(stat_size);

        if (file_size == 0) {
            _ = self.files_processed.fetchAdd(1, .monotonic);
            return FileParseResult{
                .accounts = &[_]ParsedAccount{},
                .lamports_total = 0,
            };
        }

        // mmap the file for zero-copy parsing — avoids allocating + copying entire file
        const mmap_size: usize = @intCast(stat_size);
        var used_mmap = false;
        const buf: []const u8 = if (std.posix.mmap(
            null,
            mmap_size,
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        )) |mapped| blk: {
            used_mmap = true;
            // Advise kernel to read ahead (sequential access pattern)
            std.posix.madvise(mapped.ptr, mmap_size, 2) catch {}; // MADV_SEQUENTIAL=2
            break :blk @as([*]const u8, @ptrCast(mapped))[0..file_size];
        } else |_| blk: {
            // Fallback to read if mmap fails
            const alloc_buf = try self.allocator.alloc(u8, file_size);
            _ = try file.readAll(alloc_buf);
            _ = self.blocking_reads.fetchAdd(1, .monotonic);
            break :blk alloc_buf;
        };
        defer {
            if (used_mmap) {
                const aligned: [*]align(4096) u8 = @alignCast(@constCast(buf.ptr));
                std.posix.munmap(aligned[0..mmap_size]);
            } else {
                self.allocator.free(@constCast(buf));
            }
        }

        const result = try self.parseBuffer(buf, slot);

        _ = self.files_processed.fetchAdd(1, .monotonic);
        _ = self.accounts_parsed.fetchAdd(@intCast(result.accounts.len), .monotonic);
        _ = self.bytes_processed.fetchAdd(file_size, .monotonic);

        return result;
    }

    /// Get current stats
    pub fn getStats(self: *Self) struct { files: u64, accounts: u64, bytes: u64 } {
        return .{
            .files = self.files_processed.load(.monotonic),
            .accounts = self.accounts_parsed.load(.monotonic),
            .bytes = self.bytes_processed.load(.monotonic),
        };
    }

    /// Load snapshot directory in parallel
    /// Returns total accounts loaded and lamports
    pub fn loadSnapshotParallel(
        self: *Self,
        snapshot_dir: []const u8,
        accounts_db: anytype,
    ) !struct { accounts_loaded: u64, lamports_total: u64 } {
        const start_time = std.time.milliTimestamp();

        // Enable bulk loading mode if available (faster inserts)
        if (@typeInfo(@TypeOf(accounts_db)) != .null) {
            if (@hasDecl(@TypeOf(accounts_db.*), "enableBulkLoading")) {
                accounts_db.enableBulkLoading();
            }
        }
        defer {
            // Disable bulk loading mode when done
            if (@typeInfo(@TypeOf(accounts_db)) != .null) {
                if (@hasDecl(@TypeOf(accounts_db.*), "disableBulkLoading")) {
                    accounts_db.disableBulkLoading();
                }
            }
        }

        // Phase 0: Parse manifest for file_sz map + accounts_lt_hash
        // carrier-414371294 (2026-06-10): a merged full+incremental extraction
        // has TWO manifests. Bank state (lthash/bank_hash/stakes/block_id)
        // comes from the PRIMARY (highest = incremental) manifest, but
        // appendvec file lengths must be keyed by ARCHIVE PROVENANCE: files
        // shipped by the FULL archive (slot ≤ full_slot) use the FULL
        // manifest's lengths; the incremental's post-shrink lengths apply only
        // to its own files (slot > full_slot). Mirrors Agave's
        // get_storage_lengths_for_snapshot_slots(base_slot). See
        // snapshot_manifest.mergeFileSzMapsByProvenance.
        const manifest_slots = snapshot_manifest.findManifestSlots(self.allocator, snapshot_dir) catch
            snapshot_manifest.ManifestSlots{ .primary = 0, .full = null };
        const manifest_slot = manifest_slots.primary;
        // carrier #13: record the full slot = incremental base_slot so the
        // per-record loaders apply the selective zero-lamport-tombstone rule.
        // Only set when this is a TWO-manifest (full+incremental) load.
        self.incremental_base_slot = manifest_slots.full;
        if (manifest_slots.full) |fb| {
            std.log.info("[ParallelLoader] incremental load: full/base slot={d}; incremental zero-lamport records will be inserted as tombstones (carrier #13)\n", .{fb});
        }
        var snapshot_lthash: ?[2048]u8 = null;
        var file_sz_map = if (manifest_slot > 0) blk: {
            const m = snapshot_manifest.parseManifest(self.allocator, snapshot_dir, manifest_slot) catch |err| {
                std.log.debug("[ParallelLoader] Manifest parse failed (slot={d}): {} — using stat() sizes\n", .{ manifest_slot, err });
                break :blk snapshot_manifest.FileSzMap.init(self.allocator);
            };
            std.log.debug("[ParallelLoader] Manifest parsed: {d} AppendVec sizes loaded, {d} staked vote accounts captured, {d} per-epoch stake tables\n", .{
                m.file_sz_map.count(), m.vote_account_stakes.len, m.epoch_stakes.len,
            });
            snapshot_lthash = m.accounts_lt_hash;
            if (m.bank_hash) |bh| self.snapshot_bank_hash = bh;
            if (m.last_blockhash) |lbh| self.snapshot_blockhash = lbh;
            if (m.block_height) |bh| self.snapshot_block_height = bh;
            if (m.capitalization) |cap| self.snapshot_capitalization = cap;
            // CONSENSUS-CRITICAL (epoch-979): restore the fee-rate governor +
            // signature_count so the first post-boot per-slot derivation matches.
            if (m.fee_rate_governor) |g| self.snapshot_fee_rate_governor = g;
            if (m.signature_count) |sc| self.snapshot_signature_count = sc;
            // task #28: capture the EFFECTIVE PoH cadence (was discarded). hashes_per_tick None =
            // low-power → keep the 62500 testnet default rather than 0.
            if (m.hashes_per_tick) |hpt| {
                if (hpt > 1) self.snapshot_hashes_per_tick = hpt;
            }
            // verify_ticks: preserve the RAW Option (un-defaulted) for canonical
            // `unwrap_or(0)` semantics in the tick-validity gate.
            self.snapshot_hashes_per_tick_raw = m.hashes_per_tick;
            if (m.ticks_per_slot > 0) self.snapshot_ticks_per_slot = m.ticks_per_slot;
            std.log.warn("[Manifest] PoH cadence: hashes_per_tick={d} ticks_per_slot={d}", .{ self.snapshot_hashes_per_tick, self.snapshot_ticks_per_slot });
            // d28pp (2026-05-12): canonical SIMD-0340 block_id from snapshot tail.
            if (m.block_id) |bid| {
                self.snapshot_block_id = bid;
                const bid8: [8]u8 = bid[0..8].*;
                std.log.info("[ParallelLoader] ✅ snapshot block_id extracted: first8={any} — SIMD-0340 anchor reference\n", .{bid8});
            } else {
                std.log.info("[ParallelLoader] ⚠️  snapshot has no block_id (older format) — d28oo first-shred adoption will fill at slot anchor+1\n", .{});
            }
            self.snapshot_vote_stakes = m.vote_account_stakes;
            self.snapshot_vote_frozen = m.vote_frozen_data;
            self.snapshot_epoch_stakes = m.epoch_stakes;
            // F1: capture the PRIMARY manifest's hard-fork list (the full
            // manifest's, mf.hard_forks below, is bank-side and freed there).
            self.snapshot_hard_forks = m.hard_forks;
            if (m.hard_forks.len > 0) {
                std.log.info("[ParallelLoader] ✅ {d} hard fork(s) captured from manifest (highest slot={d}) — F2/F3 source\n", .{
                    m.hard_forks.len, m.hard_forks[m.hard_forks.len - 1].slot,
                });
            }

            // carrier-414371294: parse the FULL archive's manifest too (when
            // present) and merge lengths by provenance. On any failure keep
            // the primary map (pre-fix behavior) — full files whose
            // incremental len is short will be caught by the tail-scan
            // fallback in mmapAndIndex and recovered LOUDLY.
            if (manifest_slots.full) |full_slot| {
                if (snapshot_manifest.parseManifest(self.allocator, snapshot_dir, full_slot)) |mf| {
                    var mf_map = mf.file_sz_map;
                    defer mf_map.deinit();
                    // Free the full manifest's bank-side captures — bank state
                    // comes from the primary manifest only.
                    for (mf.epoch_stakes) |es| {
                        if (es.vote_account_stakes.len > 0) self.allocator.free(es.vote_account_stakes);
                        if (es.node_pubkeys.len > 0) self.allocator.free(es.node_pubkeys);
                    }
                    if (mf.epoch_stakes.len > 0) self.allocator.free(mf.epoch_stakes);
                    if (mf.vote_account_stakes.len > 0) self.allocator.free(mf.vote_account_stakes);
                    // F1: the full manifest's hard_forks is bank-side too — the
                    // primary manifest (m.hard_forks, captured above) is the
                    // authoritative list; free this one to avoid a leak.
                    if (mf.hard_forks.len > 0) self.allocator.free(@constCast(mf.hard_forks));

                    if (snapshot_manifest.mergeFileSzMapsByProvenance(
                        self.allocator,
                        full_slot,
                        &mf_map,
                        &m.file_sz_map,
                    )) |merged| {
                        var primary_map = m.file_sz_map;
                        primary_map.deinit();
                        break :blk merged;
                    } else |err| {
                        std.log.warn("[ParallelLoader] file_sz provenance merge failed ({s}) — using primary manifest lengths only", .{@errorName(err)});
                    }
                } else |err| {
                    std.log.warn("[ParallelLoader] full manifest parse failed (slot={d}, {s}) — using primary manifest lengths only", .{ full_slot, @errorName(err) });
                }
            }
            break :blk m.file_sz_map;
        } else blk: {
            std.log.debug("[ParallelLoader] No manifest found — using stat() sizes\n", .{});
            break :blk snapshot_manifest.FileSzMap.init(self.allocator);
        };
        defer file_sz_map.deinit();

        // Store extracted lthash for bootstrap to retrieve
        if (snapshot_lthash) |lt| {
            self.snapshot_lthash = lt;
            std.log.debug("[ParallelLoader] ✅ accounts_lt_hash extracted from manifest ({d} bytes)\n", .{lt.len});
        }

        // Build accounts path
        const accounts_path = try std.fs.path.join(self.allocator, &.{ snapshot_dir, "accounts" });
        defer self.allocator.free(accounts_path);

        // Phase 1: Collect all file paths, ids, and slots.
        // r53-fix: parse the slot prefix from "<slot>.<id>" filenames and pass
        // it through to mmapAndIndex so each AccountLocation lands at the
        // right slot. Pre-r53 every insert used slot=0, which made r52's
        // higher-slot-wins guard a no-op — full's SlotHistory could clobber
        // the incremental's, leaving ~96k stale bits at boot.
        var file_paths = std.ArrayListUnmanaged([]const u8){};
        var file_ids = std.ArrayListUnmanaged(u64){};
        var file_slots = std.ArrayListUnmanaged(u64){};
        defer {
            for (file_paths.items) |p| self.allocator.free(p);
            file_paths.deinit(self.allocator);
            file_ids.deinit(self.allocator);
            file_slots.deinit(self.allocator);
        }

        var accounts_dir = try fs.cwd().openDir(accounts_path, .{ .iterate = true });
        defer accounts_dir.close();

        var iter = accounts_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            // Files must be "<slot>.<id>". Skip anything else — defaulting to 0
            // would re-enable the bug r52+r53 closes.
            const dot_pos = std.mem.lastIndexOf(u8, entry.name, ".") orelse continue;
            const slot = std.fmt.parseInt(u64, entry.name[0..dot_pos], 10) catch continue;
            const id = std.fmt.parseInt(u64, entry.name[dot_pos + 1 ..], 10) catch continue;
            const full_path = try std.fs.path.join(self.allocator, &.{ accounts_path, entry.name });
            try file_paths.append(self.allocator, full_path);
            try file_ids.append(self.allocator, id);
            try file_slots.append(self.allocator, slot);
        }

        const num_files = file_paths.items.len;
        if (num_files == 0) {
            return .{ .accounts_loaded = 0, .lamports_total = 0 };
        }

        std.log.debug("[ParallelLoader] Found {d} files, using {d} threads\n", .{
            num_files, self.config.num_threads,
        });

        // Single-pass: mmap each file → scan accounts → register as Agave store → insert index.
        // No data copy, no Phase 3/4 separation. ~60x faster than parse+reserialize.
        var accounts_loaded_atomic = std.atomic.Value(u64).init(0);
        var lamports_total_atomic = std.atomic.Value(u64).init(0);
        var error_count_atomic = std.atomic.Value(u64).init(0);

        const files_per_thread = (num_files + self.config.num_threads - 1) / self.config.num_threads;

        const MmapWorkerCtx = struct {
            loader: *Self,
            file_paths: []const []const u8,
            file_ids: []const u64,
            // r53-fix: per-file slot, indexed in lock-step with file_paths/file_ids.
            file_slots: []const u64,
            file_sz_map: *const std.AutoHashMap(u128, u64),
            start_idx: usize,
            end_idx: usize,
            accounts_db: @TypeOf(accounts_db),
            accounts_loaded: *std.atomic.Value(u64),
            lamports_total: *std.atomic.Value(u64),
            error_count: *std.atomic.Value(u64),
        };

        const mmapWorkerFn = struct {
            fn work(ctx: *MmapWorkerCtx) void {
                var i = ctx.start_idx;
                while (i < ctx.end_idx) : (i += 1) {
                    // r71-fix-4: lookup by (slot, id) tuple — keying by id
                    // alone caused 39 same-id-different-slot collisions where
                    // a small file_sz from one slot's record clobbered the
                    // correct (much larger) file_sz of another slot's file.
                    const fkey = (@as(u128, ctx.file_slots[i]) << 64) | @as(u128, ctx.file_ids[i]);
                    const file_sz = ctx.file_sz_map.get(fkey);
                    const result = ctx.loader.mmapAndIndex(
                        ctx.file_paths[i],
                        ctx.file_slots[i],
                        file_sz,
                        ctx.accounts_db,
                    ) catch |err| {
                        const cur = ctx.error_count.fetchAdd(1, .monotonic);
                        // r72-perm-fix (2026-05-05): keep the first 5 errors at .warn
                        // so a future regression in extract permissions is caught
                        // immediately rather than silently. Cheap — only fires on
                        // actual error, capped at 5.
                        if (cur < 5) {
                            std.log.warn("[ParallelLoader] mmapAndIndex FAILED file={s} slot={d} file_sz={any} err={s}", .{
                                ctx.file_paths[i], ctx.file_slots[i], file_sz, @errorName(err),
                            });
                        }
                        continue;
                    };
                    _ = ctx.accounts_loaded.fetchAdd(result.accounts_indexed, .monotonic);
                    _ = ctx.lamports_total.fetchAdd(result.lamports_total, .monotonic);
                }
            }
        }.work;

        var threads = try self.allocator.alloc(Thread, self.config.num_threads);
        defer self.allocator.free(threads);
        var contexts = try self.allocator.alloc(MmapWorkerCtx, self.config.num_threads);
        defer self.allocator.free(contexts);

        var spawned: usize = 0;
        for (0..self.config.num_threads) |t| {
            const start_idx = t * files_per_thread;
            if (start_idx >= num_files) break;
            const end_idx = @min(start_idx + files_per_thread, num_files);

            contexts[t] = MmapWorkerCtx{
                .loader = self,
                .file_paths = file_paths.items,
                .file_ids = file_ids.items,
                .file_slots = file_slots.items,
                .file_sz_map = &file_sz_map,
                .start_idx = start_idx,
                .end_idx = end_idx,
                .accounts_db = accounts_db,
                .accounts_loaded = &accounts_loaded_atomic,
                .lamports_total = &lamports_total_atomic,
                .error_count = &error_count_atomic,
            };

            threads[t] = try Thread.spawn(.{}, mmapWorkerFn, .{&contexts[t]});
            spawned += 1;
        }

        for (threads[0..spawned]) |t| {
            t.join();
        }

        const accounts_loaded = accounts_loaded_atomic.load(.monotonic);
        const lamports_total = lamports_total_atomic.load(.monotonic);
        const error_count = error_count_atomic.load(.monotonic);

        const total_time = std.time.milliTimestamp() - start_time;
        // r72-carrier-hunt: bumped to .warn so it fires at default log_level
        std.log.warn("[ParallelLoader] Total: {d} accounts in {d}ms ({d} errors)\n", .{
            accounts_loaded, total_time, error_count,
        });

        // carrier-414371294 (2026-06-10): ALWAYS print — accounts_skipped_by_len_mismatch
        // MUST be 0 on a healthy boot; recovered>0 means a manifest length was
        // wrong but every truncated record was re-indexed (see per-file
        // [SNAPLOAD-LEN-MISMATCH] lines above for which files).
        std.log.warn("[SNAPLOAD-LEN-SUMMARY] len_mismatch_files={d} accounts_recovered_by_len_mismatch={d} accounts_skipped_by_len_mismatch={d}\n", .{
            self.len_mismatch_files.load(.monotonic),
            self.accounts_recovered_len_mismatch.load(.monotonic),
            self.accounts_skipped_len_mismatch.load(.monotonic),
        });

        return .{
            .accounts_loaded = accounts_loaded,
            .lamports_total = lamports_total,
        };
    }
};

/// Generate synthetic test AppendVec files
pub fn generateTestFixture(allocator: Allocator, output_dir: []const u8, num_files: usize, accounts_per_file: usize) !void {
    // Create output directory
    fs.cwd().makeDir(output_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const accounts_dir_path = try std.fs.path.join(allocator, &.{ output_dir, "accounts" });
    defer allocator.free(accounts_dir_path);

    fs.cwd().makeDir(accounts_dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Create version file
    const version_path = try std.fs.path.join(allocator, &.{ output_dir, "version" });
    defer allocator.free(version_path);

    var version_file = try fs.cwd().createFile(version_path, .{});
    try version_file.writeAll("1.2.0\n");
    version_file.close();

    // Generate AppendVec files
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    for (0..num_files) |file_idx| {
        var filename_buf: [64]u8 = undefined;
        const filename = try std.fmt.bufPrint(&filename_buf, "{d}.{d}", .{ file_idx * 1000, file_idx });

        const file_path = try std.fs.path.join(allocator, &.{ accounts_dir_path, filename });
        defer allocator.free(file_path);

        const file = try fs.cwd().createFile(file_path, .{});
        defer file.close();

        // Write accounts to file
        for (0..accounts_per_file) |acc_idx| {
            // Generate random account
            var pubkey: [32]u8 = undefined;
            random.bytes(&pubkey);

            var owner: [32]u8 = undefined;
            random.bytes(&owner);

            const data_len: u64 = random.intRangeAtMost(u64, 0, 1024);
            const lamports: u64 = random.intRangeAtMost(u64, 1, 1_000_000_000);
            const rent_epoch: u64 = random.intRangeAtMost(u64, 0, 1000);
            const executable: u8 = if (random.boolean()) 1 else 0;

            // Write StoredMeta
            const write_version: u64 = @intCast(acc_idx + 1);
            try file.writeAll(std.mem.asBytes(&std.mem.nativeToLittle(u64, write_version)));
            try file.writeAll(std.mem.asBytes(&std.mem.nativeToLittle(u64, data_len)));
            try file.writeAll(&pubkey);

            // Write AccountMeta
            try file.writeAll(std.mem.asBytes(&std.mem.nativeToLittle(u64, lamports)));
            try file.writeAll(std.mem.asBytes(&std.mem.nativeToLittle(u64, rent_epoch)));
            try file.writeAll(&owner);
            try file.writeAll(&[_]u8{executable});
            try file.writeAll(&[_]u8{0} ** 7); // padding

            // Write Hash (32 zero bytes) — required between AccountMeta and data
            try file.writeAll(&[_]u8{0} ** 32);

            // Write data
            if (data_len > 0) {
                const data = try allocator.alloc(u8, @intCast(data_len));
                defer allocator.free(data);
                random.bytes(data);
                try file.writeAll(data);
            }

            // Align to 8 bytes — record includes StoredMeta + AccountMeta + Hash + data
            const record_len = 48 + 56 + 32 + @as(usize, @intCast(data_len));
            const pad = (8 - (record_len % 8)) & 7;
            if (pad > 0) {
                try file.writeAll(([_]u8{0} ** 8)[0..pad]);
            }
        }
    }

    std.log.debug("[TestFixture] Generated {d} files with {d} accounts each in {s}\n", .{
        num_files, accounts_per_file, output_dir,
    });
}

// ============================================================================
// Tests
// ============================================================================

test "generate and parse test fixture" {
    const allocator = std.testing.allocator;
    const test_dir = "/tmp/vexor-parallel-test";

    // Clean up any previous test
    fs.cwd().deleteTree(test_dir) catch {};

    // Generate test fixture: 10 files, 100 accounts each
    try generateTestFixture(allocator, test_dir, 10, 100);

    // Parse one file
    var loader = ParallelSnapshotLoader.init(allocator, .{});

    const accounts_path = try std.fs.path.join(allocator, &.{ test_dir, "accounts", "0.0" });
    defer allocator.free(accounts_path);

    var result = try loader.parseAppendVec(accounts_path, 0);
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 100), result.accounts.len);
    try std.testing.expect(result.lamports_total > 0);

    // Clean up
    fs.cwd().deleteTree(test_dir) catch {};
}

test "benchmark parallel vs sequential" {
    const allocator = std.testing.allocator;
    const test_dir = "/tmp/vexor-bench-test";

    // Clean up any previous test
    fs.cwd().deleteTree(test_dir) catch {};

    // Generate realistic test fixture: 50 files, 2000 accounts each = 100k accounts
    // Real AppendVecs are larger files (several MB), few large files is more realistic
    try generateTestFixture(allocator, test_dir, 50, 2000);

    var loader = ParallelSnapshotLoader.init(allocator, .{ .verbose = true });

    // Collect file paths
    const accounts_dir_path = try std.fs.path.join(allocator, &.{ test_dir, "accounts" });
    defer allocator.free(accounts_dir_path);

    var accounts_dir = try fs.cwd().openDir(accounts_dir_path, .{ .iterate = true });
    defer accounts_dir.close();

    var file_paths = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (file_paths.items) |p| allocator.free(p);
        file_paths.deinit(allocator);
    }

    var iter = accounts_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const full_path = try std.fs.path.join(allocator, &.{ accounts_dir_path, entry.name });
        try file_paths.append(allocator, full_path);
    }

    std.log.debug("\n[Benchmark] Found {d} files\n", .{file_paths.items.len});

    // Sequential parse (baseline)
    const seq_start = std.time.milliTimestamp();
    var seq_accounts: u64 = 0;
    for (file_paths.items) |path| {
        var result = try loader.parseAppendVec(path, 0);
        seq_accounts += result.accounts.len;
        result.deinit(allocator);
    }
    const seq_end = std.time.milliTimestamp();
    const seq_ms = seq_end - seq_start;

    std.log.debug("[Benchmark] Sequential: {d} accounts in {d}ms\n", .{ seq_accounts, seq_ms });

    // Reset stats
    loader.files_processed = std.atomic.Value(u64).init(0);
    loader.accounts_parsed = std.atomic.Value(u64).init(0);

    // Parallel parse - spawn threads manually for benchmark
    const par_start = std.time.milliTimestamp();
    const files_per_thread = (file_paths.items.len + loader.config.num_threads - 1) / loader.config.num_threads;

    const WorkCtx = struct {
        ldr: *ParallelSnapshotLoader,
        paths: []const []const u8,
        start: usize,
        end: usize,
        alloc: Allocator,

        fn work(ctx: *@This()) void {
            var i = ctx.start;
            while (i < ctx.end) : (i += 1) {
                var res = ctx.ldr.parseAppendVec(ctx.paths[i], 0) catch continue;
                res.deinit(ctx.alloc);
            }
        }
    };

    var threads = try allocator.alloc(Thread, loader.config.num_threads);
    defer allocator.free(threads);

    var ctxs = try allocator.alloc(WorkCtx, loader.config.num_threads);
    defer allocator.free(ctxs);

    var spawned: usize = 0;
    for (0..loader.config.num_threads) |t| {
        const s = t * files_per_thread;
        if (s >= file_paths.items.len) break;
        const e = @min(s + files_per_thread, file_paths.items.len);

        ctxs[t] = WorkCtx{
            .ldr = &loader,
            .paths = file_paths.items,
            .start = s,
            .end = e,
            .alloc = allocator,
        };
        threads[t] = try Thread.spawn(.{}, WorkCtx.work, .{&ctxs[t]});
        spawned += 1;
    }

    for (threads[0..spawned]) |th| th.join();

    const par_stats = loader.getStats();
    const par_end = std.time.milliTimestamp();
    const par_ms = par_end - par_start;

    std.log.debug("[Benchmark] Parallel:   {d} accounts in {d}ms ({d} threads)\n", .{ par_stats.accounts, par_ms, spawned });

    // Calculate speedup
    if (par_ms > 0) {
        const speedup = @as(f64, @floatFromInt(seq_ms)) / @as(f64, @floatFromInt(par_ms));
        std.log.debug("[Benchmark] Speedup: {d:.2}x\n", .{speedup});
    }

    // Clean up
    fs.cwd().deleteTree(test_dir) catch {};
}
