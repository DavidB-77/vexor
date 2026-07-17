//! Snapshot Manifest Parser
//!
//! Extracts `file_sz` for each AppendVec from the Bincode-encoded snapshot manifest.
//!
//! The manifest lives at: <snapshot_dir>/snapshots/<SLOT>/<SLOT>
//! It is a Bincode-serialized struct:
//!   { bank: DeserializableVersionedBank, accounts_db: AccountsDbFields, lps: u64 }
//!
//! We only need `accounts_db.storages[].account_vecs[].{id, file_sz}` — everything else
//! is skipped. Without `file_sz`, loading uses `stat().size` which includes Agave's
//! pre-allocated zero padding, causing the zero-terminator to fire early and only
//! ~10% of accounts to be read from each file.
//!
//! Reference layout (ripatel's Informal Guide to Solana Snapshots):
//!   https://gist.github.com/ripatel-fd/268c88d938075537ec6431e2960f47dd
//!
//! Bincode encoding rules:
//!   bool      → 1 byte (0 or 1)
//!   u8..u128  → LE bytes (1,2,4,8,16)
//!   f64       → 8 bytes LE
//!   Option<T> → 1 byte + T if present
//!   Vec<T>    → u64 count + count×T
//!   Map<K,V>  → u64 count + count×(K,V)
//!   Struct    → fields in declaration order, no padding
//!   Enum      → u32 variant_id + variant data

const std = @import("std");

/// CONSENSUS-CRITICAL: snapshot-restored fee-rate governor (epoch-979 tip
/// carrier fix). The canonical type lives in vex_svm (blockhash_queue.zig); we
/// reuse it so the captured values flow into the root bank's governor unchanged.
pub const FeeRateGovernor = @import("vex_svm").blockhash_queue.FeeRateGovernor;

// TODO: Wire bincode from vex_network when module root exports it
const bincode = struct {
    pub const BincodeError = error{BincodeParseError};
    pub const Deserializer = struct {
        data: []const u8,
        pos: usize,
        const Self = @This();
        pub fn init(data: []const u8) Self {
            return .{ .data = data, .pos = 0 };
        }
        pub fn readU64LE(self: *Self) !u64 {
            if (self.pos + 8 > self.data.len) return error.BincodeParseError;
            const val = std.mem.readInt(u64, self.data[self.pos..][0..8], .little);
            self.pos += 8;
            return val;
        }
        pub fn readBytes(self: *Self, len: usize) ![]const u8 {
            if (self.pos + len > self.data.len) return error.BincodeParseError;
            const slice = self.data[self.pos .. self.pos + len];
            self.pos += len;
            return slice;
        }
        pub fn readU64(self: *Self) !u64 {
            return self.readU64LE();
        }
        pub fn readU32(self: *Self) !u32 {
            if (self.pos + 4 > self.data.len) return error.BincodeParseError;
            const val = std.mem.readInt(u32, self.data[self.pos..][0..4], .little);
            self.pos += 4;
            return val;
        }
        pub fn readU8(self: *Self) !u8 {
            if (self.pos >= self.data.len) return error.BincodeParseError;
            const val = self.data[self.pos];
            self.pos += 1;
            return val;
        }
        pub fn readVecLength(self: *Self) !u64 {
            return self.readU64LE();
        }
        pub fn skip(self: *Self, len: usize) !void {
            self.pos = @min(self.pos + len, self.data.len);
        }
    };
};
const Deserializer = bincode.Deserializer;

const ParseError = error{
    FileNotFound,
    ReadFailed,
    MalformedManifest,
    OutOfMemory,
} || bincode.BincodeError;

/// file_sz map: key = (slot, AppendVec id) packed as u128 (slot << 64 | id),
/// value = valid byte count.
///
/// r71-fix-4 (2026-04-28): pre-fix key was `id` only. AppendVec ids are NOT
/// globally unique across the merged full+incremental snapshot — Agave's
/// snapshot extraction can produce multiple (slot, id) pairs sharing the
/// same id (39 such duplicates observed in testnet slot 404,692,481 snapshot).
/// The last `map.put(id, ...)` won, clobbering the correct file_sz for older
/// slots — e.g. `316733740.45741` (4,978,717 bytes, contains GJHtFqM9 program
/// account at offset 289,424) was overwritten by a different id-45741 file
/// with file_sz=3037, causing parser to stop after 3,037 bytes and drop ~73M
/// accounts. Mitigation: include `slot` in the key. Loader matches by the
/// per-file slot prefix from `<slot>.<id>` filenames. Files whose (slot, id)
/// is not in the manifest fall back to stat_size (zero-terminator detection).
pub const FileSzMap = std.AutoHashMap(u128, u64);

/// Pack a (slot, id) pair into the FileSzMap key.
pub inline fn fileKey(slot: u64, id: u64) u128 {
    return (@as(u128, slot) << 64) | @as(u128, id);
}

/// Result of parsing the snapshot manifest
/// One { vote_pubkey → pre-aggregated stake } row from the snapshot's
/// `Stakes.vote_accounts` map. Captured during manifest parse so Bank can
/// compute SIMD-0001 stake-weighted Clock.unix_ts without a separate stake
/// scan over AccountsDb.
pub const VoteAccountStake = struct {
    vote_pubkey: [32]u8,
    stake: u64,
};

/// One scheduled hard fork captured from the snapshot bank's
/// `hard_forks: HardForks{ hard_forks: Vec<(u64, usize)> }` blob (wire =
/// `Vec<(u64, u64)>`, sorted ascending by slot). Mirrors Agave's
/// `solana_hard_forks::HardForks` entry. The cluster registers each fork
/// pre-snapshot, so Vexor only LOADS the list for replay/voting — it never
/// calls `register_hard_fork` (no `--hard-fork` CLI path; that is a future
/// block-production add). Consumed by:
///   * F2 — bank-hash mixin: `Bank.getHashData(slot, parent_slot)` folds a
///     fork's `count` into the bank hash when a fork lands in (parent, slot].
///   * F3 — `LastRestartSlot` sysvar: highest `fork_slot ≤ slot`.
/// HARD-FORK-FAMILY-DESIGN-2026-06-17. DORMANT on post-restart testnet (all
/// post-fork slots have parent_slot ≥ fork_slot ⇒ getHashData → None).
pub const HardFork = struct {
    slot: u64,
    count: u64,
};

/// One epoch's frozen vote-account stake table, captured from the snapshot's
/// `epoch_stakes: Vec<(u64, EpochStakes)>` blob. Mirrors Agave's
/// `Bank::epoch_vote_accounts(epoch)` source for SIMD-0001 weighting.
/// d16 (2026-05-10): added so `computeStakeWeightedClockEstimate` weights by
/// the epoch-frozen set instead of the snapshot's live `Stakes::vote_accounts`
/// (which contains every vote account ever known — ~15k vs ~580 actually
/// staked for the current epoch).
pub const EpochStakesEntry = struct {
    epoch: u64,
    vote_account_stakes: []VoteAccountStake,
    /// d28zz: parallel slice (same len + indexing as `vote_account_stakes`)
    /// holding the node_pubkey captured from each frozen vote_account's data
    /// (offset 4..36 — VoteState V1_14_11/V3/V4 invariant). Source for the
    /// leader-schedule generator; mirrors Agave's `vote_account.node_pubkey()`
    /// which reads from the snapshot's frozen vote_account, not live AccountsDb.
    /// All-zero entries indicate the parser couldn't capture (short data); the
    /// schedule generator falls back to live AccountsDb for those.
    node_pubkeys: []const [32]u8 = &[_][32]u8{},
    /// carrier #16: parallel slice (same indexing) of each frozen vote
    /// account's legacy commission PERCENT (Agave VoteStateView::commission()
    /// semantics; V4 = min(bps/100,255)). Source for the boundary DELAYED
    /// commission chain (delay_commission_updates). Empty for legacy parses.
    commission_percent: []const u8 = &.{},
    /// carrier #16: parallel RAW bps (V4: inflation_rewards_commission_bps;
    /// pre-V4: percent×100). Used when commission_rate_in_basis_points is active.
    commission_bps: []const u16 = &.{},
};

pub const ManifestResult = struct {
    file_sz_map: FileSzMap,
    /// accounts_lt_hash from BankFields — the authoritative LtHash for this snapshot.
    /// null if parsing failed or the field wasn't present.
    accounts_lt_hash: ?[2048]u8 = null,
    /// Bank hash from snapshot BankFields — needed for correct parent_hash chain.
    bank_hash: ?[32]u8 = null,
    /// Block height from snapshot BankFields.
    block_height: ?u64 = null,
    /// Total lamport supply (capitalization) from snapshot BankFields.
    /// Used for accurate inflation reward calculations at epoch boundary.
    capitalization: ?u64 = null,
    /// task #28: PoH cadence from the snapshot bank (effective, NOT genesis). hashes_per_tick is
    /// Option<u64>; null => low-power/unset. ticks_per_slot defaults 64. Consumed by the block
    /// producer + PoH verifier (replaces the hardcoded genesis 12500).
    hashes_per_tick: ?u64 = null,
    ticks_per_slot: u64 = 64,
    /// CONSENSUS-CRITICAL (epoch-979 tip carrier): snapshot-restored fee-rate
    /// governor + the snapshot slot's signature_count. Seed the root bank's
    /// `fee_rate_governor` / `signature_count` at bootstrap so the first per-slot
    /// `FeeRateGovernor.newDerived` matches Agave rc.1. `signature_count` never
    /// feeds a bank_hash (root bank_hash is loaded, not recomputed).
    fee_rate_governor: ?FeeRateGovernor = null,
    signature_count: ?u64 = null,
    /// d28pp (2026-05-12): SIMD-0340 chained_block_id — the snapshot anchor's
    /// last-shred merkle root, written into the snapshot file at the tail
    /// (Agave v4.0.0-beta.6+ Hypothesis-B layout). Vexor's parser previously
    /// PROBED for this 32-byte value to position the lthash read correctly
    /// but DISCARDED the value. Wiring it through to root_bank.block_id at
    /// bootstrap unblocks SIMD-0340 fork-orphan detection from slot anchor+1
    /// onward (instead of waiting until child's first shred to adopt a
    /// possibly-forked claim, see d28oo first-shred adoption).
    /// null if the snapshot uses the older block_id=None layout.
    block_id: ?[32]u8 = null,
    /// last_blockhash (BlockhashQueue.last_hash) of the snapshot slot — the last
    /// PoH entry hash, distinct from bank_hash. Threaded to root_bank.poh_hash so
    /// the post-snapshot boundary EpochRewards `parent_blockhash` is canonical.
    /// null/zero if the manifest used None. carrier #16 @414812256.
    last_blockhash: ?[32]u8 = null,
    /// Snapshot's live `Stakes::vote_accounts` blob — every vote account ever
    /// known. Useful for top_votes seeding (account-state lookup) but NOT a
    /// faithful Agave mirror for SIMD-0001 weighting. See `epoch_stakes` below.
    /// Owned by this result; caller must free via `allocator.free`.
    vote_account_stakes: []VoteAccountStake = &[_]VoteAccountStake{},
    /// carrier #16: parallel slice (same indexing as vote_account_stakes) of
    /// FROZEN vote account data from the serialized stakes cache. Owned.
    vote_frozen_data: []const []const u8 = &.{},
    /// Snapshot's `epoch_stakes` blob: per-epoch frozen vote-account stake
    /// tables. Indexed at runtime by `current_epoch` to mirror Agave's
    /// `epoch_vote_accounts(epoch)`. Owned by this result; each entry's
    /// `vote_account_stakes` slice must be freed via `allocator.free`.
    epoch_stakes: []const EpochStakesEntry = &[_]EpochStakesEntry{},
    /// F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): the bank's `hard_forks` list
    /// captured from the manifest (previously discarded by `skipHardForks`).
    /// Sorted ascending by slot (Agave invariant). Allocator-owned; moved into
    /// the loader (`snapshot_hard_forks`) → AccountsDb (`hard_forks`); freed in
    /// `AccountsDb.deinit`. Drives F2 (bank-hash mixin) + F3 (LastRestartSlot).
    hard_forks: []const HardFork = &[_]HardFork{},
};

/// Parse the snapshot manifest and return a map of AppendVec id → file_sz.
/// The caller owns the returned map and must call map.deinit().
pub fn parseManifest(
    allocator: std.mem.Allocator,
    snapshot_dir: []const u8,
    slot: u64,
) ParseError!ManifestResult {
    // Build path: <snapshot_dir>/snapshots/<slot>/<slot>
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/snapshots/{d}/{d}", .{
        snapshot_dir, slot, slot,
    }) catch return error.MalformedManifest;

    const file = std.fs.cwd().openFile(path, .{}) catch return error.FileNotFound;
    defer file.close();

    const stat = file.stat() catch return error.ReadFailed;
    const data = allocator.alloc(u8, stat.size) catch return error.OutOfMemory;
    defer allocator.free(data);

    const n = file.readAll(data) catch return error.ReadFailed;
    if (n != stat.size) return error.ReadFailed;

    var cur = Deserializer.init(data);
    return parseManifestFromBytes(allocator, &cur);
}

fn parseManifestFromBytes(allocator: std.mem.Allocator, cur: *Deserializer) ParseError!ManifestResult {
    // Save cursor position in case bank skip fails (v4.0 format changes)
    // Agave v4.0 modified several bank fields (rent_collector, epoch, collector_fees)
    // If skipBank() misaligns, fall back gracefully to empty map (stat() sizes used)

    // Step 1: Parse bank section (extract bank_hash + block_height + vote stakes)
    const bank_fields = skipBank(allocator, cur) catch |err| {
        std.log.warn("[Manifest] skipBank failed ({}) — snapshot may use v4.0 format. " ++
            "Falling back to stat() file sizes (account loading still works, just less precise).", .{err});
        return ManifestResult{ .file_sz_map = FileSzMap.init(allocator) };
    };

    // Step 2: Read accounts_db.storages — this is what we came for
    const file_sz_map = readStorages(allocator, cur) catch |err| {
        std.log.warn("[Manifest] readStorages failed ({}) — falling back to stat() file sizes.", .{err});
        return ManifestResult{ .file_sz_map = FileSzMap.init(allocator) };
    };

    // d16 (2026-05-10): forward-walk between storages and ExtraFields'
    // accounts_lt_hash to capture the snapshot's `versioned_epoch_stakes`
    // blob (Agave's authoritative source for SIMD-0001 Clock weighting).
    // Snapshots contain per-epoch frozen vote-account stake tables here,
    // computed by Agave at epoch boundary; replaying them mirror-faithfully
    // is the only way Vexor's stake-weighted Clock can match gov's.
    // Best-effort: any parser error → empty epoch_stakes (Bank caller
    // returns null Clock estimate, parent inherits — same as Agave).
    const captured_epoch_stakes = readVersionedEpochStakesFromExtraFields(allocator, cur) catch |err| blk: {
        std.log.warn("[Manifest] versioned_epoch_stakes capture failed ({}) — Clock will inherit (no SW estimate)\n", .{err});
        break :blk &[_]EpochStakesEntry{};
    };
    if (captured_epoch_stakes.len > 0) {
        std.log.warn("[Manifest] ✅ versioned_epoch_stakes captured: {d} epochs from ExtraFields\n", .{captured_epoch_stakes.len});
    }

    // Step 3: Try to read accounts_lt_hash from after the storages section.
    // Layout after storages: snapshot_version(u64), historical_roots(Vec<Slot>),
    // historical_roots_with_hash(Vec<(Slot,Hash)>), then BankHashInfo, then
    // accounts_lt_hash: Option<[u8; 2048]>.
    // We attempt to navigate this; if any step fails, return without lthash.
    //
    // d28pp (2026-05-12): also extract the SIMD-0340 block_id field that
    // follows lthash in the snapshot tail (Hypothesis-B layout only — older
    // snapshots use block_id=None and we get null). Wired through to
    // root_bank.block_id at bootstrap so SIMD-0340 fork-orphan detection
    // has a canonical reference from slot anchor+1 onward (instead of the
    // d28oo first-shred adoption fallback).
    // CANONICAL (2026-06-03): forward-parse field 5/6 from the cursor (which
    // readVersionedEpochStakesFromExtraFields left exactly at field 5). The
    // corrected tail-seek is a defensive fallback only if the forward-parse's
    // strict tag+EOF validation fails (e.g. epoch_stakes parse drifted). The
    // extracted base is verified against the snapshot archive checksum in
    // bootstrap, which hard-fails the boot on mismatch — so no silently-wrong
    // base can be accepted by either path.
    const lt_and_bid = readLtHashAndBlockIdForward(cur) catch
        readLtHashAndBlockId(cur) catch LtHashAndBlockId{
        .lthash = [_]u8{0} ** 2048,
        .block_id = null,
    };
    const lthash_present = blk: {
        var any_nonzero: bool = false;
        for (lt_and_bid.lthash) |b| if (b != 0) {
            any_nonzero = true;
            break;
        };
        break :blk any_nonzero;
    };
    const lthash: ?[2048]u8 = if (lthash_present) lt_and_bid.lthash else null;
    if (lthash != null) {
        std.log.debug("[Manifest] ✅ accounts_lt_hash extracted from snapshot manifest\n", .{});
    } else {
        std.log.debug("[Manifest] ⚠️  accounts_lt_hash not found (will recompute from accounts)\n", .{});
    }

    return ManifestResult{
        .file_sz_map = file_sz_map,
        .accounts_lt_hash = lthash,
        .bank_hash = bank_fields.bank_hash,
        .block_height = bank_fields.block_height,
        .capitalization = bank_fields.capitalization,
        .fee_rate_governor = bank_fields.fee_rate_governor,
        .signature_count = bank_fields.signature_count,
        .hashes_per_tick = bank_fields.hashes_per_tick,
        .ticks_per_slot = bank_fields.ticks_per_slot,
        .vote_account_stakes = bank_fields.vote_account_stakes,
        .vote_frozen_data = bank_fields.vote_frozen_data,
        .epoch_stakes = captured_epoch_stakes,
        .block_id = lt_and_bid.block_id,
        .last_blockhash = if (std.mem.allEqual(u8, &bank_fields.last_blockhash, 0)) null else bank_fields.last_blockhash,
        // F1: forward the captured hard-fork list (moved from BankFields).
        .hard_forks = bank_fields.hard_forks,
    };
}

/// One node's leader-schedule-boot entry recovered from a serialized manifest's
/// `versioned_epoch_stakes` block. TEST-ONLY surface (see
/// `readEpochStakesBootSubsetForTest`) — the LIVE reader skips these maps.
pub const EpochStakesBootNode = struct {
    node: [32]u8,
    vote_count: usize,
    node_stake: u64,
};

/// One epoch's leader-schedule-boot subset.
pub const EpochStakesBootEntry = struct {
    epoch: u64,
    total_stake: u64,
    /// Allocator-owned; caller frees.
    nodes: []EpochStakesBootNode,
};

/// TEST-ONLY: re-read the FULL `versioned_epoch_stakes` boot subset (the parts
/// the live reader SKIPS: `total_stake` + `node_id_to_vote_accounts`) from a
/// fully-serialized manifest byte stream. Walks the same prefix the live reader
/// does (`skipBank` → `readStorages` → the AccountsDbFields-tail/ExtraFields
/// prefix) to reach the block, then reads each entry capturing total_stake and
/// the node→(vote_count, node_stake) map. Used by `test-snapshot-create` to
/// prove the boot-relevant maps round-trip (a green live-reader round-trip alone
/// only proves the per-vote subset). Caller frees the returned slice and each
/// entry's `nodes`.
pub fn readEpochStakesBootSubsetForTest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ParseError![]EpochStakesBootEntry {
    var cur = Deserializer.init(bytes);
    // Prefix: bank section + storages (discarded), matching parseManifestFromBytes.
    const bf = try skipBank(allocator, &cur);
    // Free anything skipBank captured (we only want the position advanced).
    if (bf.vote_account_stakes.len > 0) allocator.free(bf.vote_account_stakes);
    for (bf.vote_frozen_data) |fd| if (fd.len > 0) allocator.free(@constCast(fd));
    if (bf.vote_frozen_data.len > 0) allocator.free(@constCast(bf.vote_frozen_data));
    for (bf.epoch_stakes) |es| if (es.vote_account_stakes.len > 0) allocator.free(es.vote_account_stakes);
    if (bf.epoch_stakes.len > 0) allocator.free(@constCast(bf.epoch_stakes));
    if (bf.hard_forks.len > 0) allocator.free(@constCast(bf.hard_forks));
    var fsm = try readStorages(allocator, &cur);
    fsm.deinit();
    // AccountsDbFields-tail + ExtraFields prefix (mirror of
    // readVersionedEpochStakesFromExtraFields), then read the Vec capturing maps.
    cur.skip(8 + 8 + 104) catch return error.MalformedManifest;
    {
        const c = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(c * 8)) catch return error.MalformedManifest;
    }
    {
        const c = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(c * 40)) catch return error.MalformedManifest;
    }
    cur.skip(8) catch return error.MalformedManifest; // lamports_per_signature
    {
        const tag = cur.readU8() catch return error.MalformedManifest;
        if (tag == 1) cur.skip(88) catch return error.MalformedManifest;
    }
    {
        const tag = cur.readU8() catch return error.MalformedManifest;
        if (tag == 1) cur.skip(32) catch return error.MalformedManifest;
    }
    const count = cur.readVecLength() catch return error.MalformedManifest;
    if (count > 1024) return error.MalformedManifest;
    const out = allocator.alloc(EpochStakesBootEntry, @intCast(count)) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const epoch = cur.readU64() catch return error.MalformedManifest;
        const variant = cur.readU32() catch return error.MalformedManifest;
        if (variant != 0) return error.MalformedManifest;
        // vote_accounts: Vec<(Pubkey, u64, SolanaAccount)> — skip, keeping count.
        const va_count = cur.readVecLength() catch return error.MalformedManifest;
        var v: u64 = 0;
        while (v < va_count) : (v += 1) {
            try skipPubkey(&cur); // vote_pubkey
            cur.skip(8) catch return error.MalformedManifest; // stake
            try skipSolanaAccount(&cur); // SolanaAccount
        }
        // stake_delegations + epoch + stake_history (skip).
        const sd_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // unused header
        cur.skip(@intCast(sd_count * (32 + 72))) catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // stakes.epoch
        const sh_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(sh_count * 32)) catch return error.MalformedManifest;
        // total_stake (CAPTURE).
        const total_stake = cur.readU64() catch return error.MalformedManifest;
        // node_id_to_vote_accounts: Vec<(Pubkey, (Vec<Pubkey>, u64))> (CAPTURE).
        const niva_count = cur.readVecLength() catch return error.MalformedManifest;
        const nodes = allocator.alloc(EpochStakesBootNode, @intCast(niva_count)) catch return error.OutOfMemory;
        errdefer allocator.free(nodes);
        var ni: u64 = 0;
        while (ni < niva_count) : (ni += 1) {
            const node_pk = cur.readBytes(32) catch return error.MalformedManifest;
            const inner = cur.readVecLength() catch return error.MalformedManifest;
            cur.skip(@intCast(inner * 32)) catch return error.MalformedManifest; // vote pubkeys
            const node_stake = cur.readU64() catch return error.MalformedManifest;
            nodes[ni] = .{ .node = node_pk[0..32].*, .vote_count = @intCast(inner), .node_stake = node_stake };
        }
        // epoch_authorized_voters: Vec<(Pubkey, Pubkey)> — skip.
        const eav_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(eav_count * 64)) catch return error.MalformedManifest;
        out[i] = .{ .epoch = epoch, .total_stake = total_stake, .nodes = nodes };
    }
    return out;
}

/// Read accounts_lt_hash from the snapshot manifest using a tail-seek.
///
/// Agave v4.0.0-beta.4 ExtraFields binary layout (appended after AccountsDbFields):
///   1. lamports_per_signature:                    u64         (8 bytes)
///   2. Option<UnusedIncrementalSnapshotPersistence>            (1 or 89 bytes)
///   3. Option<Hash> (unused_epoch_accounts_hash)               (1 or 33 bytes)
///   4. Vec<(u64, DeserializableVersionedEpochStakes)>          (variable-length!)
///   5. Option<SerdeAccountsLtHash = [u16;1024]>                (1 + 2048 bytes) ← WANT
///   6. Option<Hash> (block_id)                                 (1 or 33 bytes)
///
/// Field 4 is variable-length and contains complex nested structs, making forward-parsing
/// impractical. Instead, we seek from the tail of the file.
///
/// Probe-confirmed layout for testnet snapshots (block_id = None):
///   offset (file_size - 2049): 0x01  ← Option::Some tag for accounts_lt_hash
///   offset (file_size - 2048): 2048 bytes of LtHash ([u16;1024] in LE)
///   offset (file_size - 0)  : nothing (block_id = 0x00, not present / EOF)
///
/// We try two locations: block_id=None (tail-2049) and block_id=Some (tail-2083).
/// Fall back to forward-parse probe only if both tail reads fail.
/// d28pp (2026-05-12): result type carrying both lthash AND block_id.
/// `block_id` populated only when the snapshot file uses Hypothesis-B layout
/// (block_id=Some). Hypothesis-A layout (older / block_id=None) returns null.
const LtHashAndBlockId = struct {
    lthash: [2048]u8,
    block_id: ?[32]u8,
};

fn readLtHash(cur: *Deserializer) ParseError![2048]u8 {
    const both = try readLtHashAndBlockId(cur);
    return both.lthash;
}

/// CANONICAL forward-parse of `accounts_lt_hash` (field 5) and `block_id`
/// (field 6) from the CURRENT cursor position.
///
/// `parseManifestFromBytes` has already forward-parsed fields 1-4 (including
/// the variable-length `versioned_epoch_stakes` Vec) via
/// `readVersionedEpochStakesFromExtraFields`, which leaves `cur` positioned
/// exactly at field 5 in Agave's bincode ExtraFields order:
///   5. Option<SerdeAccountsLtHash = [u16;1024]>   (1 tag + 2048 bytes)
///   6. Option<Hash> (block_id)                     (1 tag + 0/32 bytes)
///
/// This matches Agave's deserialize order EXACTLY instead of guessing byte
/// offsets from the tail. The old tail-seek (`readLtHashAndBlockId`) was
/// off-by-one for the 4.1 (SIMD-0340, block_id=Some) layout and grabbed a
/// 14-byte-misaligned window as the lattice BASE — corrupting every replayed
/// slot's bank_hash (root cause, 2026-06-03).
///
/// Strict validation: both Option tags must be valid discriminants (0 or 1)
/// AND the cursor must land EXACTLY at end-of-manifest after field 6 (block_id
/// is the final ExtraField in 4.1.0-beta.1/beta.2). Any deviation ⇒ error, so
/// the caller falls back to the corrected tail-seek; bootstrap's archive-
/// checksum guard is the authoritative gate over whichever path is taken.
fn readLtHashAndBlockIdForward(cur: *Deserializer) ParseError!LtHashAndBlockId {
    // field 5: Option<accounts_lt_hash>
    const lt_tag = cur.readU8() catch return error.MalformedManifest;
    if (lt_tag != 0 and lt_tag != 1) return error.MalformedManifest; // misaligned cursor
    var lthash: [2048]u8 = [_]u8{0} ** 2048;
    if (lt_tag == 1) {
        const b = cur.readBytes(2048) catch return error.MalformedManifest;
        @memcpy(&lthash, b[0..2048]);
    }
    // field 6: Option<Hash> block_id
    const bid_tag = cur.readU8() catch return error.MalformedManifest;
    if (bid_tag != 0 and bid_tag != 1) return error.MalformedManifest;
    var block_id: ?[32]u8 = null;
    if (bid_tag == 1) {
        const b = cur.readBytes(32) catch return error.MalformedManifest;
        var bid: [32]u8 = undefined;
        @memcpy(&bid, b[0..32]);
        block_id = bid;
    }
    // Structural check: ExtraFields end after block_id — cursor must be at EOF.
    // If not, fields 1-4 were mis-parsed (or the format gained a trailing
    // field) and this extraction is unreliable.
    if (cur.pos != cur.data.len) return error.MalformedManifest;
    if (block_id) |bid| {
        const bid8: [8]u8 = bid[0..8].*;
        std.log.debug("[Manifest] ✅ LtHash+block_id via forward-parse (canonical): block_id first8={any}\n", .{bid8});
    } else {
        std.log.debug("[Manifest] ✅ LtHash via forward-parse (canonical); block_id=None\n", .{});
    }
    return .{ .lthash = lthash, .block_id = block_id };
}

/// DEFENSIVE FALLBACK tail-seek for `accounts_lt_hash` + `block_id`. Used only
/// when the canonical forward-parse (`readLtHashAndBlockIdForward`) fails its
/// strict validation. ExtraFields end with `Option<accounts_lt_hash>` then
/// `Option<Hash> block_id`, so the lt_hash Option tag sits at exactly one of
/// three fixed offsets from EOF (bincode always emits the Option discriminant
/// byte):
///   - block_id = Some : [lt_tag][2048][bid_tag=01][32]  ⇒ lt_tag @ fs-2082
///   - block_id = None : [lt_tag][2048][bid_tag=00]      ⇒ lt_tag @ fs-2050
///   - no block_id field (pre-SIMD-0340): [lt_tag][2048] ⇒ lt_tag @ fs-2049
///
/// Each candidate is accepted only if its tag is 0x01, its 2048-byte window is
/// substantively non-zero, AND its trailing bytes match the layout exactly
/// (ending precisely at EOF). The prior implementation used `fs-2083` for the
/// Some case (off by one) and then a heuristic backward scan that locked onto
/// a spurious 0x01 byte INSIDE the lt_hash data — extracting a 14-byte-
/// misaligned base lattice. That heuristic scan is removed: a wrong base is
/// catastrophic (it silently corrupts every replayed slot), so we only accept
/// a layout-exact candidate and otherwise error out (bootstrap then hard-fails
/// rather than booting on a guessed base).
fn readLtHashAndBlockId(cur: *Deserializer) ParseError!LtHashAndBlockId {
    const file_data = cur.data;
    const file_size = file_data.len;
    if (file_size < 2060) return error.MalformedManifest;

    const Cand = struct { lt_off: usize, trailing: usize };
    const cands = [_]Cand{
        .{ .lt_off = file_size - 2082, .trailing = 33 }, // block_id = Some
        .{ .lt_off = file_size - 2050, .trailing = 1 }, // block_id = None
        .{ .lt_off = file_size - 2049, .trailing = 0 }, // no block_id field
    };
    for (cands) |c| {
        if (file_data[c.lt_off] != 0x01) continue; // lt_hash Option must be Some
        const win = file_data[c.lt_off + 1 .. c.lt_off + 2049];
        var nonzero: usize = 0;
        for (win) |b| {
            if (b != 0) nonzero += 1;
        }
        if (nonzero <= 64) continue;
        const tail_off = c.lt_off + 2049; // first byte after the lt_hash window
        // Trailing structure must match the layout exactly AND end at EOF.
        if (tail_off + c.trailing != file_size) continue;
        var block_id: ?[32]u8 = null;
        if (c.trailing == 33) {
            if (file_data[tail_off] != 0x01) continue; // block_id Option must be Some
            var bid: [32]u8 = undefined;
            @memcpy(&bid, file_data[tail_off + 1 .. tail_off + 33]);
            block_id = bid;
        } else if (c.trailing == 1) {
            if (file_data[tail_off] != 0x00) continue; // block_id Option must be None
        }
        var result: [2048]u8 = undefined;
        @memcpy(&result, win);
        const f8: [8]u8 = result[0..8].*;
        std.log.debug("[Manifest] ✅ LtHash via corrected tail-seek (lt_off=fs-{d}, trailing={d}): first8={any}\n", .{ file_size - c.lt_off, c.trailing, f8 });
        return .{ .lthash = result, .block_id = block_id };
    }

    std.log.debug("[Manifest] ❌ LtHash not found — no layout-exact tail candidate (file_size={d})\n", .{file_size});
    return error.MalformedManifest;
}

fn readStorages(allocator: std.mem.Allocator, cur: *Deserializer) ParseError!FileSzMap {
    var map = FileSzMap.init(allocator);
    errdefer map.deinit();

    // storages: Vec<SnapshotSlotAccVecs>
    const slot_count = cur.readVecLength() catch return error.MalformedManifest;
    if (slot_count > 1_000_000) return error.MalformedManifest; // sanity

    var s: u64 = 0;
    while (s < slot_count) : (s += 1) {
        // r71-fix-4: read slot (was previously skipped — see FileSzMap doc).
        const slot = cur.readU64() catch return error.MalformedManifest;

        // account_vecs: Vec<SnapshotAccVec>
        const vec_count = cur.readVecLength() catch return error.MalformedManifest;
        if (vec_count > 100_000) return error.MalformedManifest;

        var v: u64 = 0;
        while (v < vec_count) : (v += 1) {
            const id = cur.readU64() catch return error.MalformedManifest;
            const file_sz = cur.readU64() catch return error.MalformedManifest;
            map.put(fileKey(slot, id), file_sz) catch return error.OutOfMemory;
        }
    }

    return map;
}

// ── Bank skipper ──────────────────────────────────────────────────────────────
//
// We skip `deserializable_versioned_bank` field by field following the Bincode
// schema. The bank is the only thing standing between the start of the manifest
// and the accounts_db section.

const BankFields = struct {
    bank_hash: [32]u8 = [_]u8{0} ** 32,
    block_height: u64 = 0,
    capitalization: u64 = 0,
    /// Number of transaction signatures accumulated by the snapshot slot. Seeds
    /// the root bank's signature_count → the FIRST per-slot governor derivation.
    /// Captured from the manifest (was skipped). NEVER feeds a bank_hash.
    signature_count: u64 = 0,
    /// CONSENSUS-CRITICAL fee-rate governor restored from the snapshot. Its
    /// `lamports_per_signature` comes from the bank-level fee_calculator u64; the
    /// other 5 fields from the 33-byte fee_rate_governor block. Seeds the root
    /// bank's `fee_rate_governor` so per-slot `newDerived` matches Agave rc.1.
    fee_rate_governor: FeeRateGovernor = .{},
    /// task #28: PoH cadence from the snapshot bank. hashes_per_tick is Option<u64> (None=low-power).
    /// Effective testnet value = 62500 (raised from genesis 12500 by long-activated
    /// update_hashes_per_tick; Agave 4.x carries it forward in the snapshot). ticks_per_slot=64.
    /// Previously DISCARDED — the producer/verifier hardcoded the wrong genesis 12500.
    hashes_per_tick: ?u64 = null,
    ticks_per_slot: u64 = 64,
    /// last_blockhash (BlockhashQueue.last_hash) = the snapshot slot's last PoH
    /// entry hash. Distinct from bank_hash. Zero-filled if the manifest had None.
    last_blockhash: [32]u8 = [_]u8{0} ** 32,
    /// Snapshot-epoch vote_account → stake. Allocator-owned; moved into
    /// ManifestResult.vote_account_stakes on success.
    vote_account_stakes: []VoteAccountStake = &[_]VoteAccountStake{},
    /// carrier #16: parallel slice of FROZEN vote account data (same indexing).
    vote_frozen_data: []const []const u8 = &.{},
    /// d16 (2026-05-10): per-epoch frozen vote-account stake tables (Agave's
    /// `epoch_stakes` blob). Allocator-owned; moved into ManifestResult.
    epoch_stakes: []const EpochStakesEntry = &[_]EpochStakesEntry{},
    /// F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): `hard_forks` list captured
    /// mid-`skipBank` by `parseHardForks` (was discarded by `skipHardForks`).
    /// Allocator-owned; moved into ManifestResult.hard_forks.
    hard_forks: []const HardFork = &[_]HardFork{},
};

fn skipBank(allocator: std.mem.Allocator, cur: *Deserializer) ParseError!BankFields {
    var fields = BankFields{};
    if (try parseBlockhashQueue(cur)) |lbh| fields.last_blockhash = lbh;
    std.log.debug("[Debug] parseBlockhashQueue passed (last_blockhash captured)\n", .{});
    try skipVec(cur, skipSlotPair); // ancestors: Vec<(u64, u64)>
    std.log.debug("[Debug] ancestors passed\n", .{});
    // READ bank hash instead of skipping — critical for parent_hash chain
    const hash_bytes = cur.readBytes(32) catch return error.MalformedManifest;
    @memcpy(&fields.bank_hash, hash_bytes[0..32]);
    std.log.debug("[Manifest] bank_hash: {x:0>2}{x:0>2}{x:0>2}{x:0>2}...\n", .{
        fields.bank_hash[0], fields.bank_hash[1], fields.bank_hash[2], fields.bank_hash[3],
    });
    try skipHash(cur); // parent_hash: [32]u8
    cur.skip(8) catch {
        std.log.debug("[Debug] parent_slot failed\n", .{});
        return error.MalformedManifest;
    }; // parent_slot: u64
    // F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): CAPTURE hard_forks instead of
    // skipping. parseHardForks reads the IDENTICAL bytes skipHardForks did
    // (8-byte len + len×16) so every downstream field (transaction_count@512,
    // capitalization@515, hashes_per_tick@517 …) stays byte-aligned. Verified
    // by the test-hard-fork F1 cursor KAT (cursor advances 8+len×16 exactly,
    // matching skipHardForks). Allocator-owned; moved into ManifestResult.
    fields.hard_forks = try parseHardForks(allocator, cur); // hard_forks
    std.log.debug("[Debug] hard_forks passed ({d} forks)\n", .{fields.hard_forks.len});
    cur.skip(8) catch {
        std.log.debug("[Debug] transaction_count failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] tick_height failed\n", .{});
        return error.MalformedManifest;
    };
    // CAPTURE signature_count (was skipped). Same cursor advance (8 bytes). The
    // root bank's signature_count seeds the FIRST post-boot per-slot governor
    // derivation (newDerived(root.governor, root.signature_count)); without it
    // the first derivation would use 0 and diverge from Agave's restored value
    // whenever the snapshot slot itself saw a signature spike (>10000 sigs at
    // the canonical testnet target). It NEVER feeds a bank_hash (root bank_hash
    // is loaded from the manifest, not recomputed; child banks reset to 0).
    fields.signature_count = cur.readU64() catch {
        std.log.debug("[Debug] signature_count failed\n", .{});
        return error.MalformedManifest;
    };
    fields.capitalization = cur.readU64() catch {
        std.log.debug("[Debug] capitalization failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] max_tick_height failed\n", .{});
        return error.MalformedManifest;
    };
    fields.hashes_per_tick = readOptionU64(cur) catch {
        std.log.debug("[Debug] hashes_per_tick failed\n", .{});
        return error.MalformedManifest;
    }; // Option<u64> — CAPTURE (task #28: was discarded; effective testnet=62500, genesis=12500)
    fields.ticks_per_slot = cur.readU64() catch {
        std.log.debug("[Debug] ticks_per_slot failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(16) catch {
        std.log.debug("[Debug] ns_per_slot failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] genesis_creation_time failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] slots_per_year failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] accounts_data_len failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] slot failed\n", .{});
        return error.MalformedManifest;
    };
    cur.skip(8) catch {
        std.log.debug("[Debug] epoch failed\n", .{});
        return error.MalformedManifest;
    };
    fields.block_height = cur.readU64() catch {
        std.log.debug("[Debug] block_height failed\n", .{});
        return error.MalformedManifest;
    };
    try skipPubkey(cur); // collector_id: Pubkey
    cur.skip(8) catch {
        std.log.debug("[Debug] collector_fees failed\n", .{});
        return error.MalformedManifest;
    };
    // CAPTURE the bank-level fee_calculator (u64 = the seed/current
    // lamports_per_signature) instead of skipping (same 8-byte advance).
    fields.fee_rate_governor.lamports_per_signature = cur.readU64() catch {
        std.log.debug("[Debug] fee_calculator failed\n", .{});
        return error.MalformedManifest;
    };
    // CAPTURE the 5 fee_rate_governor fields (same 33-byte advance as the old
    // skipFeeRateGovernor — byte alignment is parity-critical and KAT-validated).
    try readFeeRateGovernor(cur, &fields.fee_rate_governor); // fee_rate_governor
    std.log.debug("[Debug] fee_rate_governor passed (target_lps={d} target_sps={d})\n", .{
        fields.fee_rate_governor.target_lamports_per_signature,
        fields.fee_rate_governor.target_signatures_per_slot,
    });
    cur.skip(8) catch {
        std.log.debug("[Debug] collected_rent failed\n", .{});
        return error.MalformedManifest;
    };
    try skipRentCollector(cur); // rent_collector
    std.log.debug("[Debug] rent_collector passed\n", .{});
    try skipEpochSchedule(cur); // epoch_schedule
    std.log.debug("[Debug] epoch_schedule passed\n", .{});
    try skipInflation(cur); // inflation
    std.log.debug("[Debug] inflation passed\n", .{});
    fields.vote_account_stakes = try readStakesCapturingVoteAccounts(allocator, cur, &fields.vote_frozen_data);
    std.log.debug("[Debug] stakes passed ({d} staked vote accounts)\n", .{fields.vote_account_stakes.len});
    try skipUnusedAccounts(cur); // unused_accounts
    // d16 (2026-05-10) NOTE: in Agave 4.0+ the bank section's analogue is
    // `unused_epoch_stakes: HashMap<Epoch, ()>` — always empty. The REAL
    // `versioned_epoch_stakes: Vec<(u64, DeserializableVersionedEpochStakes)>`
    // is in ExtraFields. We capture it via `readVersionedEpochStakesFromTail`
    // after the ExtraFields lthash tail-seek runs.
    try skipVec(cur, skipEpochStakesPair); // epoch_stakes: HashMap<Epoch, ()> (empty in v4.0)
    cur.skip(1) catch return error.MalformedManifest; // is_delta: bool
    return fields;
}

// ── Bank field skippers ───────────────────────────────────────────────────────

/// Parse the BlockhashQueue, CAPTURING `last_hash` (= the bank's last_blockhash,
/// i.e. the last PoH entry hash of the snapshot slot). Returns null if the
/// Option<Hash> is None. carrier #16 @414812256: this is the canonical source
/// for the boundary EpochRewards sysvar `parent_blockhash` and for the root
/// bank's inherited poh_hash — it is NOT the same as the bank_hash (the prior
/// r66 shortcut conflated them).
fn parseBlockhashQueue(cur: *Deserializer) ParseError!?[32]u8 {
    cur.skip(8) catch return error.MalformedManifest; // last_hash_index: u64
    var last_hash: ?[32]u8 = null;
    const present = cur.readU8() catch return error.MalformedManifest; // last_hash: Option<Hash>
    if (present != 0) {
        const hb = cur.readBytes(32) catch return error.MalformedManifest;
        var h: [32]u8 = undefined;
        @memcpy(&h, hb[0..32]);
        last_hash = h;
    }
    // ages: Vec<(Hash(32), HashAge{fee_calc:u64, hash_index:u64, timestamp:u64})>
    // Each entry = 32 + 24 = 56 bytes
    const count = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(count * 56)) catch return error.MalformedManifest;
    cur.skip(8) catch return error.MalformedManifest; // max_age: u64
    return last_hash;
}

/// F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): parse `hard_forks: HardForks{
/// hard_forks: Vec<(u64, usize)> }` (wire = `Vec<(u64, u64)>`) CAPTURING each
/// (slot, count) pair instead of discarding it (the old `skipHardForks` did
/// `skipVec(cur, skipSlotPair)`). The byte cursor advances EXACTLY as the
/// skip did — 8-byte LE length, then `len × 16` (two u64 LE) — so no downstream
/// manifest field shifts (the parity-critical invariant; KAT-asserted). The
/// returned slice is allocator-owned; the caller moves it into
/// BankFields.hard_forks → ManifestResult. On a corrupted/huge length the
/// allocation fails with error.OutOfMemory, which `parseManifestFromBytes`'s
/// `skipBank catch` turns into the graceful empty-ManifestResult fallback.
fn parseHardForks(allocator: std.mem.Allocator, cur: *Deserializer) ParseError![]const HardFork {
    const count = cur.readVecLength() catch return error.MalformedManifest;
    if (count == 0) return &[_]HardFork{};
    const list = allocator.alloc(HardFork, @intCast(count)) catch return error.OutOfMemory;
    errdefer allocator.free(list);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const fork_slot = cur.readU64() catch return error.MalformedManifest;
        const fork_count = cur.readU64() catch return error.MalformedManifest;
        list[@intCast(i)] = .{ .slot = fork_slot, .count = fork_count };
    }
    return list;
}

/// F1 KAT helper (HARD-FORK-FAMILY-DESIGN-2026-06-17): parse a raw hard_forks
/// blob (8-byte LE len + len×16) and report BOTH the captured list and the EXACT
/// byte count consumed. The cursor-advance assertion (`consumed == 8 + len*16`)
/// is the parity-critical invariant — the deleted `skipHardForks` consumed the
/// same `8 + len*16`, so this absolute count is the faithful "cursor where
/// skipHardForks would have left it" check. The returned `forks` slice is
/// allocator-owned (caller frees). Exposed for test-hard-fork; not on any boot
/// path (the boot path calls `parseHardForks` mid-`skipBank`).
pub const HardForksParseTest = struct { forks: []const HardFork, consumed: usize };
pub fn parseHardForksForTest(allocator: std.mem.Allocator, bytes: []const u8) ParseError!HardForksParseTest {
    var cur = Deserializer.init(bytes);
    const forks = try parseHardForks(allocator, &cur);
    return .{ .forks = forks, .consumed = cur.pos };
}

/// CAPTURE the fee_rate_governor block instead of skipping it. The cursor
/// advances EXACTLY the same 33 bytes the old `skipFeeRateGovernor` consumed
/// (4×u64 + u8) — byte alignment is parity-critical (validated by the manifest
/// cursor KAT). The caller has already populated `gov.lamports_per_signature`
/// from the preceding bank-level fee_calculator u64; this fills the other 5.
/// Wire order (Agave `FeeRateGovernor` serde): target_lps, target_sps, min_lps,
/// max_lps, burn_percent.
fn readFeeRateGovernor(cur: *Deserializer, gov: *FeeRateGovernor) ParseError!void {
    gov.target_lamports_per_signature = cur.readU64() catch return error.MalformedManifest;
    gov.target_signatures_per_slot = cur.readU64() catch return error.MalformedManifest;
    gov.min_lamports_per_signature = cur.readU64() catch return error.MalformedManifest;
    gov.max_lamports_per_signature = cur.readU64() catch return error.MalformedManifest;
    gov.burn_percent = cur.readU8() catch return error.MalformedManifest;
}

fn skipRentCollector(cur: *Deserializer) ParseError!void {
    cur.skip(8) catch return error.MalformedManifest; // epoch: u64
    try skipEpochSchedule(cur); // epoch_schedule
    cur.skip(8) catch return error.MalformedManifest; // slots_per_year: f64
    try skipRent(cur); // rent
}

fn skipEpochSchedule(cur: *Deserializer) ParseError!void {
    // slots_per_epoch, leader_schedule_slot_offset: 2×u64 = 16
    // warmup: bool (1)
    // first_normal_epoch, first_normal_slot: 2×u64 = 16
    cur.skip(33) catch return error.MalformedManifest;
}

fn skipRent(cur: *Deserializer) ParseError!void {
    // lamports_per_uint8_year: u64(8), exemption_threshold: f64(8), burn_pct: u8(1)
    cur.skip(17) catch return error.MalformedManifest;
}

fn skipInflation(cur: *Deserializer) ParseError!void {
    // initial, terminal, taper, foundation, foundation_term, __unused: 6×f64
    cur.skip(48) catch return error.MalformedManifest;
}

/// Capturing variant of the obsolete `skipStakes`: reads the Stakes blob's
/// `vote_accounts` map into a heap-allocated `[]VoteAccountStake` and skips
/// past the remaining stake_delegations / stake_history fields. Caller owns
/// the returned slice.
fn readStakesCapturingVoteAccounts(
    allocator: std.mem.Allocator,
    cur: *Deserializer,
    captured_frozen_out: *[]const []const u8,
) ParseError![]VoteAccountStake {
    // vote_accounts: { vote_accounts: Map<Pubkey, (u64, SolanaAccount)> }
    const va_count = cur.readVecLength() catch return error.MalformedManifest;
    var stakes = allocator.alloc(VoteAccountStake, @intCast(va_count)) catch return error.OutOfMemory;
    errdefer allocator.free(stakes);

    // carrier #16 (2026-06-12): PARALLEL slice (same indexing as the returned
    // stakes) holding each entry's FROZEN SolanaAccount.data from the serialized
    // stakes-cache map. Canonical Agave reads vote credit windows for epoch-
    // boundary points from THIS frozen copy (epoch_stakes clone of the loaded
    // cache), not live accountsdb — they differ for dormant votes.
    var frozen = allocator.alloc([]const u8, @intCast(va_count)) catch return error.OutOfMemory;
    errdefer allocator.free(frozen);
    @memset(frozen, &.{});

    var idx: u64 = 0;
    while (idx < va_count) : (idx += 1) {
        const pk_bytes = cur.readBytes(32) catch return error.MalformedManifest;
        @memcpy(&stakes[idx].vote_pubkey, pk_bytes[0..32]);
        stakes[idx].stake = cur.readU64() catch return error.MalformedManifest;
        // value.1: SolanaAccount { lamports u64, data Vec<u8>, owner Pubkey, executable u8, rent_epoch u64 }
        cur.skip(8) catch return error.MalformedManifest; // lamports
        const fdata_len = cur.readVecLength() catch return error.MalformedManifest;
        if (fdata_len > 10 * 1024 * 1024) return error.MalformedManifest;
        const fdata = cur.readBytes(@intCast(fdata_len)) catch return error.MalformedManifest;
        frozen[idx] = allocator.dupe(u8, fdata) catch return error.OutOfMemory;
        try skipPubkey(cur); // owner
        cur.skip(1) catch return error.MalformedManifest; // executable
        cur.skip(8) catch return error.MalformedManifest; // rent_epoch
    }
    captured_frozen_out.* = frozen;

    // stake_delegations: Map<Pubkey, Delegation>
    // Delegation: voter_pubkey(32) + stake(8) + activation_epoch(8) +
    //             deactivation_epoch(8) + warmup_cooldown_rate(8 f64) = 64 bytes
    const sd_count = cur.readVecLength() catch return error.MalformedManifest;
    std.log.warn("[MANIFEST-STAKES] vote_accounts={d} stake_delegations={d} (carrier-16 canonical-iteration-set probe)", .{ va_count, sd_count });
    cur.skip(8) catch return error.MalformedManifest; // unused: u64
    // Each entry: Pubkey(32) + Delegation(64) = 96 bytes
    cur.skip(@intCast(sd_count * 96)) catch return error.MalformedManifest;

    cur.skip(8) catch return error.MalformedManifest; // epoch: u64
    // stake_history: Vec<(Epoch:u64, StakeHistoryEntry{u64,u64,u64}=24)>
    // Each entry = 8 + 24 = 32 bytes
    const sh_count = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(sh_count * 32)) catch return error.MalformedManifest;

    return stakes;
}

/// Legacy skip-only variant used inside nested EpochStakes entries where we
/// don't yet plumb captured stakes through the caller chain.
fn skipStakes(cur: *Deserializer) ParseError!void {
    const va_count = cur.readVecLength() catch return error.MalformedManifest;
    var i: u64 = 0;
    while (i < va_count) : (i += 1) {
        try skipPubkey(cur);
        cur.skip(8) catch return error.MalformedManifest;
        try skipSolanaAccount(cur);
    }
    const sd_count = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(8) catch return error.MalformedManifest;
    cur.skip(@intCast(sd_count * 96)) catch return error.MalformedManifest;
    cur.skip(8) catch return error.MalformedManifest;
    const sh_count = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(sh_count * 32)) catch return error.MalformedManifest;
}

fn skipUnusedAccounts(cur: *Deserializer) ParseError!void {
    // unused1: Vec<Pubkey>
    const c1 = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(c1 * 32)) catch return error.MalformedManifest;
    // unused2: Vec<Pubkey>
    const c2 = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(c2 * 32)) catch return error.MalformedManifest;
    // unused3: Vec<(Pubkey, u64)>
    const c3 = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(c3 * 40)) catch return error.MalformedManifest;
}

fn skipEpochStakesPair(cur: *Deserializer) ParseError!void {
    cur.skip(8) catch return error.MalformedManifest; // key: u64 (epoch)
    // EpochStakes:
    try skipStakes(cur); // stakes: Stakes
    cur.skip(8) catch return error.MalformedManifest; // total_stake: u64
    // node_id_to_vote_accounts: Vec<(Pubkey, NodeVoteAccounts{Vec<Pubkey>, u64})>
    const niva_count = cur.readVecLength() catch return error.MalformedManifest;
    var i: u64 = 0;
    while (i < niva_count) : (i += 1) {
        try skipPubkey(cur); // key: Pubkey
        // NodeVoteAccounts: { vote_accounts: Vec<Pubkey>, total_stake: u64 }
        const va_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(va_count * 32)) catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // total_stake: u64
    }
    // epoch_authorized_voters: Vec<(Pubkey, Pubkey)> = each 64 bytes
    const eav_count = cur.readVecLength() catch return error.MalformedManifest;
    cur.skip(@intCast(eav_count * 64)) catch return error.MalformedManifest;
}

/// d16 (2026-05-10): forward-walk from cursor-after-storages through the
/// AccountsDbFields tail + ExtraFields prefix to capture
/// `versioned_epoch_stakes: Vec<(u64, DeserializableVersionedEpochStakes)>`.
///
/// Layout (Agave 4.0, `runtime/src/serde_snapshot.rs`):
///   AccountsDbFields tail (after storages):
///     u64       unused write_version
///     u64       slot
///     104 B     BankHashInfo  (32+32+5*u64)
///     Vec<Slot>            historical_roots               (default_on_eof)
///     Vec<(Slot,Hash)>     historical_roots_with_hash     (default_on_eof)
///   ExtraFieldsToDeserialize:
///     u64                  lamports_per_signature         (default_on_eof)
///     Option<UnusedIncrementalSnapshotPersistence(88B)>   (default_on_eof)
///     Option<Hash>                                        (default_on_eof)
///     Vec<(u64, DeserializableVersionedEpochStakes)>      (default_on_eof) ← WANT
///     Option<SerdeAccountsLtHash([u16;1024])>             (default_on_eof)
///     Option<Hash> block_id                               (default_on_eof)
///
/// `default_on_eof`: any field that hits unexpected EOF defaults to its zero
/// value. Mirrored here as silent error→empty fallthrough — matches Agave's
/// behavior on truncated/older snapshots.
///
/// Caller owns the returned slice + each entry's nested `vote_account_stakes`.
fn readVersionedEpochStakesFromExtraFields(
    allocator: std.mem.Allocator,
    cur: *Deserializer,
) ParseError![]const EpochStakesEntry {
    // AccountsDbFields tail: write_version + slot + BankHashInfo
    cur.skip(8 + 8 + 104) catch return &[_]EpochStakesEntry{};
    // historical_roots: Vec<Slot>
    {
        const c = cur.readVecLength() catch return &[_]EpochStakesEntry{};
        if (c > 10_000_000) return error.MalformedManifest;
        cur.skip(@intCast(c * 8)) catch return &[_]EpochStakesEntry{};
    }
    // historical_roots_with_hash: Vec<(Slot, Hash)> = each 40 bytes
    {
        const c = cur.readVecLength() catch return &[_]EpochStakesEntry{};
        if (c > 10_000_000) return error.MalformedManifest;
        cur.skip(@intCast(c * 40)) catch return &[_]EpochStakesEntry{};
    }
    // ExtraFields: lamports_per_signature
    cur.skip(8) catch return &[_]EpochStakesEntry{};
    // Option<UnusedIncrementalSnapshotPersistence>: 1 + (88 if Some)
    {
        const tag = cur.readU8() catch return &[_]EpochStakesEntry{};
        if (tag == 1) cur.skip(88) catch return &[_]EpochStakesEntry{};
    }
    // Option<Hash>: 1 + (32 if Some)
    {
        const tag = cur.readU8() catch return &[_]EpochStakesEntry{};
        if (tag == 1) cur.skip(32) catch return &[_]EpochStakesEntry{};
    }
    // versioned_epoch_stakes: Vec<(u64, DeserializableVersionedEpochStakes)>
    return readVersionedEpochStakesVecCapturing(allocator, cur);
}

/// Read the `Vec<(u64, DeserializableVersionedEpochStakes)>` blob, capturing
/// each epoch's vote-account stake table. `DeserializableVersionedEpochStakes`
/// is a Bincode enum (one variant `Current` at u32 LE tag 0); inner is
/// `DeserializableStakes<Stake>` followed by total_stake, node_id_to_vote_accounts,
/// epoch_authorized_voters. Stake is 72 bytes (Delegation 64 + credits_observed 8).
fn readVersionedEpochStakesVecCapturing(
    allocator: std.mem.Allocator,
    cur: *Deserializer,
) ParseError![]const EpochStakesEntry {
    const count = cur.readVecLength() catch return &[_]EpochStakesEntry{};
    if (count > 1024) return error.MalformedManifest;
    if (count == 0) return &[_]EpochStakesEntry{};

    const entries = allocator.alloc(EpochStakesEntry, @intCast(count)) catch return error.OutOfMemory;
    errdefer allocator.free(entries);

    var idx: u64 = 0;
    while (idx < count) : (idx += 1) {
        const epoch = cur.readU64() catch return error.MalformedManifest;
        // Enum variant tag: u32 LE (Bincode default for derive(Deserialize) enum).
        const variant_tag = cur.readU32() catch return error.MalformedManifest;
        if (variant_tag != 0) return error.MalformedManifest; // only `Current` exists in v4.0
        // DeserializableStakes<Stake>:
        //   vote_accounts: Vec<(Pubkey, u64, SolanaAccount)>     ← capture
        //   stake_delegations: Vec<(Pubkey, Stake[72B])> + 8B unused header
        //   epoch: u64
        //   stake_history: Vec<(u64, StakeHistoryEntry[24B])>
        const va_count = cur.readVecLength() catch return error.MalformedManifest;
        if (va_count > 100_000) return error.MalformedManifest;
        const stakes = allocator.alloc(VoteAccountStake, @intCast(va_count)) catch return error.OutOfMemory;
        errdefer allocator.free(stakes);
        // d28zz: parallel slice of node_pubkeys captured from each frozen
        // vote_account's data (offset 4..36). Sized exactly like `stakes` so
        // the leader-schedule generator can pair them by index.
        const node_pks = allocator.alloc([32]u8, @intCast(va_count)) catch return error.OutOfMemory;
        errdefer allocator.free(node_pks);
        // carrier #16: parallel per-vote frozen commission percent (delayed-
        // commission source for boundary rewards).
        const comm_pcts = allocator.alloc(u8, @intCast(va_count)) catch return error.OutOfMemory;
        errdefer allocator.free(comm_pcts);
        const comm_bps = allocator.alloc(u16, @intCast(va_count)) catch return error.OutOfMemory;
        errdefer allocator.free(comm_bps);
        var v: u64 = 0;
        while (v < va_count) : (v += 1) {
            const pk_bytes = cur.readBytes(32) catch return error.MalformedManifest;
            @memcpy(&stakes[v].vote_pubkey, pk_bytes[0..32]);
            stakes[v].stake = cur.readU64() catch return error.MalformedManifest;
            // d28zz fix: capture node_pubkey from the FROZEN vote account in the
            // snapshot (matches Agave's `vote_account.node_pubkey()` source for
            // leader-schedule input). Without this, populateAgaveCanonical must
            // resolve node_pubkey via live AccountsDb which can miss vote
            // accounts → missing_acct > 0 → schedule diverges from cluster's.
            try skipSolanaAccountCapturingVoteFields(cur, &node_pks[v], &comm_pcts[v], &comm_bps[v]);
        }
        // stake_delegations: per Agave existing skipStakes pattern (u64 unused header + count*entry_size)
        const sd_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // unused: u64 header
        cur.skip(@intCast(sd_count * (32 + 72))) catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // epoch: u64
        const sh_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(sh_count * 32)) catch return error.MalformedManifest;
        // After DeserializableStakes: total_stake + node_id_to_vote_accounts + epoch_authorized_voters
        cur.skip(8) catch return error.MalformedManifest; // total_stake: u64
        const niva_count = cur.readVecLength() catch return error.MalformedManifest;
        var ni: u64 = 0;
        while (ni < niva_count) : (ni += 1) {
            try skipPubkey(cur);
            const inner_va_count = cur.readVecLength() catch return error.MalformedManifest;
            cur.skip(@intCast(inner_va_count * 32)) catch return error.MalformedManifest;
            cur.skip(8) catch return error.MalformedManifest; // node total_stake
        }
        const eav_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(eav_count * 64)) catch return error.MalformedManifest;

        entries[idx] = .{ .epoch = epoch, .vote_account_stakes = stakes, .node_pubkeys = node_pks, .commission_percent = comm_pcts, .commission_bps = comm_bps };
    }
    return entries;
}

/// d16 (2026-05-10): legacy capturing variant kept for reference; not used.
/// Was wired to bank section's `unused_epoch_stakes: HashMap<Epoch, ()>` which
/// is empty in Agave 4.0+. Real data is in ExtraFields; see
/// `readVersionedEpochStakesFromExtraFields` above.
fn readEpochStakesVecCapturing(
    allocator: std.mem.Allocator,
    cur: *Deserializer,
) ParseError![]EpochStakesEntry {
    const count = cur.readVecLength() catch return error.MalformedManifest;
    if (count > 1024) return error.MalformedManifest; // sanity bound: epoch count
    const entries = allocator.alloc(EpochStakesEntry, @intCast(count)) catch return error.OutOfMemory;
    errdefer allocator.free(entries);

    var idx: u64 = 0;
    while (idx < count) : (idx += 1) {
        const epoch = cur.readU64() catch return error.MalformedManifest;
        // Inner Stakes blob: capture vote_accounts, then skip the rest.
        const va_count = cur.readVecLength() catch return error.MalformedManifest;
        if (va_count > 100_000) return error.MalformedManifest;
        const stakes = allocator.alloc(VoteAccountStake, @intCast(va_count)) catch return error.OutOfMemory;
        errdefer allocator.free(stakes);
        var v: u64 = 0;
        while (v < va_count) : (v += 1) {
            const pk_bytes = cur.readBytes(32) catch return error.MalformedManifest;
            @memcpy(&stakes[v].vote_pubkey, pk_bytes[0..32]);
            stakes[v].stake = cur.readU64() catch return error.MalformedManifest;
            try skipSolanaAccount(cur); // value.1: SolanaAccount — data not needed
        }
        // stake_delegations: Vec<(Pubkey, Delegation=64)>; layout = u64 + count*96
        const sd_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest;
        cur.skip(@intCast(sd_count * 96)) catch return error.MalformedManifest;
        cur.skip(8) catch return error.MalformedManifest; // epoch: u64
        const sh_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(sh_count * 32)) catch return error.MalformedManifest;
        // EpochStakes wrapper continues with total_stake + node_id_to_vote_accounts + epoch_authorized_voters
        cur.skip(8) catch return error.MalformedManifest; // total_stake: u64
        const niva_count = cur.readVecLength() catch return error.MalformedManifest;
        var ni: u64 = 0;
        while (ni < niva_count) : (ni += 1) {
            try skipPubkey(cur); // key: Pubkey
            const inner_va_count = cur.readVecLength() catch return error.MalformedManifest;
            cur.skip(@intCast(inner_va_count * 32)) catch return error.MalformedManifest;
            cur.skip(8) catch return error.MalformedManifest; // node total_stake
        }
        const eav_count = cur.readVecLength() catch return error.MalformedManifest;
        cur.skip(@intCast(eav_count * 64)) catch return error.MalformedManifest;

        entries[idx] = .{ .epoch = epoch, .vote_account_stakes = stakes };
    }
    return entries;
}

fn skipSolanaAccount(cur: *Deserializer) ParseError!void {
    // { lamports: u64, data: Vec<u8>, owner: Pubkey, executable: bool, rent_epoch: u64 }
    cur.skip(8) catch return error.MalformedManifest; // lamports
    const data_len = cur.readVecLength() catch return error.MalformedManifest;
    if (data_len > 10 * 1024 * 1024) return error.MalformedManifest;
    cur.skip(@intCast(data_len)) catch return error.MalformedManifest;
    try skipPubkey(cur); // owner
    cur.skip(1) catch return error.MalformedManifest; // executable: bool
    cur.skip(8) catch return error.MalformedManifest; // rent_epoch: u64
}

/// Variant of skipSolanaAccount that captures bytes 4..36 of the data field as
/// node_pubkey (if present). Mirrors the offset used by Agave's
/// VoteStateFrame{V1_14_11,V3,V4}::node_pubkey_offset (= size_of::<u32>()).
/// All-zero `out` if data is too short.
fn skipSolanaAccountCapturingVoteNodePubkey(cur: *Deserializer, out: *[32]u8) ParseError!void {
    var comm: u8 = 0;
    var bps: u16 = 0;
    try skipSolanaAccountCapturingVoteFields(cur, out, &comm, &bps);
}

/// carrier #16 (2026-06-12): capture node_pubkey AND the legacy commission
/// PERCENT from a frozen vote account's data. Commission semantics mirror
/// Agave `VoteStateView::commission()`:
///   disc 0/1/2 (V0_23_5 / V1_14_11 / V3): u8 percent at offset 68
///     (= 4 disc + 32 node_pubkey + 32 authorized_withdrawer)
///   disc 3 (V4): u16 inflation_rewards_commission_bps at offset 132
///     (= 4 + 32 node + 32 withdrawer + 32 inflation_collector + 32
///     block_revenue_collector), percent = min(bps/100, 255).
/// Used by the epoch-boundary DELAYED commission chain (Agave
/// delay_commission_updates: epoch_stakes(rewarded) → epoch_stakes(current) →
/// live state). 0 if data too short.
fn skipSolanaAccountCapturingVoteFields(cur: *Deserializer, out: *[32]u8, commission_out: *u8, commission_bps_out: *u16) ParseError!void {
    @memset(out, 0);
    commission_out.* = 0;
    commission_bps_out.* = 0;
    cur.skip(8) catch return error.MalformedManifest; // lamports
    const data_len = cur.readVecLength() catch return error.MalformedManifest;
    if (data_len > 10 * 1024 * 1024) return error.MalformedManifest;
    if (data_len >= 134) {
        const head = cur.readBytes(134) catch return error.MalformedManifest;
        @memcpy(out, head[4..36]);
        const disc = std.mem.readInt(u32, head[0..4], .little);
        if (disc == 3) {
            const bps = std.mem.readInt(u16, head[132..134], .little);
            commission_out.* = @intCast(@min(bps / 100, 255));
            commission_bps_out.* = bps;
        } else {
            commission_out.* = head[68];
            commission_bps_out.* = @as(u16, head[68]) * 100;
        }
        cur.skip(@intCast(data_len - 134)) catch return error.MalformedManifest;
    } else if (data_len >= 36) {
        const head = cur.readBytes(36) catch return error.MalformedManifest;
        @memcpy(out, head[4..36]);
        cur.skip(@intCast(data_len - 36)) catch return error.MalformedManifest;
    } else {
        cur.skip(@intCast(data_len)) catch return error.MalformedManifest;
    }
    try skipPubkey(cur); // owner
    cur.skip(1) catch return error.MalformedManifest; // executable: bool
    cur.skip(8) catch return error.MalformedManifest; // rent_epoch: u64
}

// ── Primitive skippers ────────────────────────────────────────────────────────

fn skipHash(cur: *Deserializer) ParseError!void {
    cur.skip(32) catch return error.MalformedManifest;
}

fn skipPubkey(cur: *Deserializer) ParseError!void {
    cur.skip(32) catch return error.MalformedManifest;
}

fn skipOptionHash(cur: *Deserializer) ParseError!void {
    const present = cur.readU8() catch return error.MalformedManifest;
    if (present != 0) try skipHash(cur);
}

fn skipOptionU64(cur: *Deserializer) ParseError!void {
    const present = cur.readU8() catch return error.MalformedManifest;
    if (present != 0) cur.skip(8) catch return error.MalformedManifest;
}

/// Read an Option<u64> capturing the value. Consumes EXACTLY the same bytes as skipOptionU64
/// (1 byte None / 9 bytes Some) so downstream manifest alignment is unchanged.
fn readOptionU64(cur: *Deserializer) ParseError!?u64 {
    const present = cur.readU8() catch return error.MalformedManifest;
    if (present == 0) return null;
    return cur.readU64() catch return error.MalformedManifest;
}

fn skipSlotPair(cur: *Deserializer) ParseError!void {
    // (u64, u64) = 16 bytes
    cur.skip(16) catch return error.MalformedManifest;
}

fn skipVec(cur: *Deserializer, skipElem: fn (*Deserializer) ParseError!void) ParseError!void {
    const count = cur.readVecLength() catch return error.MalformedManifest;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        try skipElem(cur);
    }
}

/// Discover the manifest slot by listing the snapshots/ subdirectory.
/// Returns the largest numeric directory name found, or error if none.
pub fn findManifestSlot(allocator: std.mem.Allocator, snapshot_dir: []const u8) !u64 {
    const slots = try findManifestSlots(allocator, snapshot_dir);
    return slots.primary;
}

/// carrier-414371294 (2026-06-10): a merged full+incremental extraction has
/// TWO manifest dirs under snapshots/ — the FULL archive's (lower slot) and
/// the INCREMENTAL's (higher slot). `primary` = highest (the bank state to
/// boot from: lthash/bank_hash/stakes). `full` = lowest, when distinct —
/// needed because appendvec file lengths must be keyed by ARCHIVE PROVENANCE
/// (see mergeFileSzMapsByProvenance below).
pub const ManifestSlots = struct {
    /// Highest manifest slot — the incremental's (or the full's on a
    /// full-only boot). Bank fields / lthash / epoch_stakes come from here.
    primary: u64,
    /// Lowest manifest slot when ≥2 dirs exist = the FULL archive's slot.
    /// null on a full-only extraction.
    full: ?u64,
};

pub fn findManifestSlots(allocator: std.mem.Allocator, snapshot_dir: []const u8) !ManifestSlots {
    var path_buf: [512]u8 = undefined;
    const snapshots_path = std.fmt.bufPrint(&path_buf, "{s}/snapshots", .{snapshot_dir}) catch
        return error.MalformedManifest;

    var dir = std.fs.cwd().openDir(snapshots_path, .{ .iterate = true }) catch
        return error.FileNotFound;
    defer dir.close();

    var best_slot: u64 = 0;
    var min_slot: u64 = std.math.maxInt(u64);
    var num_slots: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        const slot = std.fmt.parseInt(u64, entry.name, 10) catch continue;
        num_slots += 1;
        if (slot > best_slot) best_slot = slot;
        if (slot < min_slot) min_slot = slot;
    }
    _ = allocator;
    if (best_slot == 0) return error.FileNotFound;
    if (num_slots > 2) {
        // Should never happen with deploy.sh extraction (exactly full+incr).
        // The min-slot dir is still the best full-archive candidate; warn loudly.
        std.log.warn("[Manifest] {d} manifest dirs under snapshots/ (expected ≤2) — treating min={d} as FULL, max={d} as primary", .{ num_slots, min_slot, best_slot });
    }
    return ManifestSlots{
        .primary = best_slot,
        .full = if (num_slots >= 2 and min_slot < best_slot) min_slot else null,
    };
}

/// carrier-414371294 (2026-06-10): merge the two manifests' appendvec-length
/// maps by ARCHIVE PROVENANCE, mirroring Agave's snapshot rebuilder
/// (`AccountsDbFields::get_storage_lengths_for_snapshot_slots`,
/// runtime/src/serde_snapshot.rs:101 in 4.1.0-beta.3):
///   - the FULL archive is rebuilt with the FULL manifest's lengths
///     (base_slot=None → all slots),
///   - the INCREMENTAL archive is rebuilt with the INCREMENTAL manifest's
///     lengths FILTERED to slot > full_slot (base_slot=Some(full_slot)).
///
/// Vexor previously parsed only the HIGHEST manifest (the incremental) and
/// applied its lengths to ALL files — including full-archive files. When
/// Agave shrinks a storage between the full and incremental cuts, the
/// incremental manifest records the POST-shrink (smaller) length while the
/// file on disk is the full archive's PRE-shrink layout; the truncated parse
/// silently drops the tail account(s). Proven carrier: PDA
/// 2FC547gLsf91DH83Ajs8xU32V18gNz5NEvdkSSptZ7t7 in appendvec 414364417.1455839
/// (file 131,624 B; full manifest 131,624; incremental manifest 131,488) —
/// last entry never indexed → empty-stub served → Anchor 3007 where the
/// cluster succeeds → lt divergence @414371294.
///
/// Result map (caller owns): incremental entries with slot > full_slot
/// ∪ full entries (slot ≤ full_slot). Incremental entries with
/// slot ≤ full_slot are DROPPED (Agave never uses them for rebuilding);
/// files not present in the result fall back to stat-size parsing with the
/// terminator scan, exactly as before.
pub fn mergeFileSzMapsByProvenance(
    allocator: std.mem.Allocator,
    full_slot: u64,
    full_map: *const FileSzMap,
    incr_map: *const FileSzMap,
) !FileSzMap {
    var merged = FileSzMap.init(allocator);
    errdefer merged.deinit();

    var disagreements: u64 = 0;
    var incr_dropped: u64 = 0;

    var incr_it = incr_map.iterator();
    while (incr_it.next()) |e| {
        const slot: u64 = @intCast(e.key_ptr.* >> 64);
        if (slot > full_slot) {
            try merged.put(e.key_ptr.*, e.value_ptr.*);
        } else {
            incr_dropped += 1;
        }
    }

    var full_it = full_map.iterator();
    while (full_it.next()) |e| {
        const slot: u64 = @intCast(e.key_ptr.* >> 64);
        if (slot > full_slot) {
            // Agave hard-errors on storage slots above the manifest's own slot
            // (MismatchedSnapshotStorageSlot); we keep booting but never let a
            // full-manifest entry override incremental territory.
            std.log.warn("[Manifest] full manifest has storage slot {d} > full_slot {d} — ignored", .{ slot, full_slot });
            continue;
        }
        if (incr_map.get(e.key_ptr.*)) |incr_len| {
            if (incr_len != e.value_ptr.*) {
                disagreements += 1;
                if (disagreements <= 4) {
                    const id: u64 = @truncate(e.key_ptr.*);
                    std.log.warn("[Manifest] [SNAPLOAD-LEN-PROVENANCE] storage {d}.{d}: full_len={d} incr_len={d} — using FULL (file shipped by full archive)", .{ slot, id, e.value_ptr.*, incr_len });
                }
            }
        }
        try merged.put(e.key_ptr.*, e.value_ptr.*);
    }

    std.log.warn("[Manifest] file_sz provenance merge: full_slot={d} full_entries={d} incr_entries={d} incr_dropped_le_full={d} len_disagreements={d} merged={d}", .{
        full_slot, full_map.count(), incr_map.count(), incr_dropped, disagreements, merged.count(),
    });
    return merged;
}

// ════════════════════════════════════════════════════════════════════════════
// WRITE-SIDE MANIFEST SERIALIZER (snapshot CREATION, 2026-06-21)
// ════════════════════════════════════════════════════════════════════════════
//
// This is the EXACT REVERSE of the read-side parser above. Every field is
// emitted in the SAME bincode order the parser consumes it
// (`skipBank` → `readStorages` → AccountsDbFields-tail → ExtraFields), with
// matching widths (LE ints, Vec = u64 len + elems, Option = 1 tag + payload,
// enum variant = u32 LE tag). Because the serializer mirrors the deserializer
// structurally, a round-trip through `parseManifest` recovers every captured
// field byte-for-byte. Proven by the `test-snapshot-create` round-trip KAT
// (tests/kat_snapshot_create.zig).
//
// v1 SCOPE / HONESTY BOUNDARY:
//   * All variable-length stake/epoch blobs are emitted EMPTY (count=0):
//     Stakes.vote_accounts, stake_delegations, stake_history, unused_accounts,
//     the bank-section epoch_stakes HashMap, and ExtraFields
//     versioned_epoch_stakes. This is structurally Agave-shaped and round-trips,
//     but a snapshot built this way carries NO stake tables / leader schedule —
//     loadable-by-Vexor, NOT boot-to-vote complete. (v2: emit the live stake
//     cache so the produced snapshot can bootstrap a fresh validator.)
//   * BankHashInfo content is zero-filled (the reader skips its 104 bytes).
//   * This matches the reader, which is itself proven against REAL Agave
//     snapshots on the live boot path — so the fields the reader TOUCHES are
//     Agave-structurally-compatible. NOT independently verified: Agave
//     `solana-ledger-tool` acceptance of the zero-filled skipped-field content.

const ManifestSerializer = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) ManifestSerializer {
        return .{ .allocator = allocator };
    }
    fn deinit(self: *ManifestSerializer) void {
        self.buf.deinit(self.allocator);
    }
    fn u8w(self: *ManifestSerializer, v: u8) !void {
        try self.buf.append(self.allocator, v);
    }
    fn u32w(self: *ManifestSerializer, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.buf.appendSlice(self.allocator, &b);
    }
    fn u64w(self: *ManifestSerializer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try self.buf.appendSlice(self.allocator, &b);
    }
    fn u128w(self: *ManifestSerializer, v: u128) !void {
        var b: [16]u8 = undefined;
        std.mem.writeInt(u128, &b, v, .little);
        try self.buf.appendSlice(self.allocator, &b);
    }
    fn f64w(self: *ManifestSerializer, v: f64) !void {
        try self.u64w(@bitCast(v));
    }
    fn bytesw(self: *ManifestSerializer, b: []const u8) !void {
        try self.buf.appendSlice(self.allocator, b);
    }
    fn vecLen(self: *ManifestSerializer, n: u64) !void {
        try self.u64w(n);
    }
    /// Option<u64>: 1 tag byte + (8 if Some). Mirrors readOptionU64.
    fn optU64(self: *ManifestSerializer, v: ?u64) !void {
        if (v) |x| {
            try self.u8w(1);
            try self.u64w(x);
        } else {
            try self.u8w(0);
        }
    }
    /// Option<Hash>: 1 tag byte + (32 if Some).
    fn optHash(self: *ManifestSerializer, v: ?[32]u8) !void {
        if (v) |h| {
            try self.u8w(1);
            try self.bytesw(&h);
        } else {
            try self.u8w(0);
        }
    }
    fn zeros(self: *ManifestSerializer, n: usize) !void {
        try self.buf.appendNTimes(self.allocator, 0, n);
    }
};

/// One (slot, AppendVec id, file_sz) storage entry for the manifest's
/// `storages: Vec<SnapshotSlotAccVecs>` section. Mirrors readStorages: the
/// serializer groups these by slot. `file_sz` MUST be the REAL on-disk byte
/// count of the `<slot>.<id>` appendvec (NOT accounts_written) — the loader
/// uses it as the exact valid-data length. Stat the appendvec after writing.
pub const StorageEntry = struct {
    slot: u64,
    id: u64,
    file_sz: u64,
};

/// Inputs for `serializeManifest`. Each named field maps to a captured field
/// the reader recovers; everything else is fixed-width zero/empty per v1 scope.
pub const ManifestWriteFields = struct {
    /// Bank slot this snapshot anchors at.
    slot: u64,
    /// parent_slot (BankFields).
    parent_slot: u64,
    /// bank_hash [32] (BankFields) — recovered by skipBank → fields.bank_hash.
    bank_hash: [32]u8,
    /// parent bank_hash [32].
    parent_hash: [32]u8 = [_]u8{0} ** 32,
    /// last_blockhash (BlockhashQueue.last_hash). Some => emitted as Option::Some.
    last_blockhash: ?[32]u8 = null,
    /// capitalization (total lamport supply).
    capitalization: u64,
    /// block_height (BankFields).
    block_height: u64,
    /// hashes_per_tick: Option<u64> (None = low-power).
    hashes_per_tick: ?u64 = null,
    /// ticks_per_slot.
    ticks_per_slot: u64 = 64,
    /// epoch (BankFields).
    epoch: u64 = 0,
    /// accounts_lt_hash — the REAL 2048-byte lattice hash from bank.accounts_lthash
    /// ([BANK-FROZEN] lthash_full), NOT the simple accounts_hash. Emitted as
    /// Option::Some so the loader's forward-parser recovers it exactly.
    accounts_lt_hash: [2048]u8,
    /// SIMD-0340 chained block_id. None on the legacy (block_id=None) layout.
    block_id: ?[32]u8 = null,
    /// CONSENSUS-CRITICAL for snapshot round-trip (2026-06-26): the bank's
    /// fee_rate_governor + signature_count. The reloaded root bank seeds these
    /// (bootstrap.zig:405-407) and they drive the per-slot
    /// FeeRateGovernor.newDerived → the lamports_per_signature pushed into the
    /// RecentBlockhashes sysvar EVERY slot (bank.zig:1571-1573). null => the
    /// serializer emits zeros (legacy behavior); set => the FIRST replayed slot's
    /// RBH sysvar matches, avoiding the epoch-979 carrier-class divergence.
    fee_rate_governor: ?FeeRateGovernor = null,
    signature_count: ?u64 = null,
    /// storages: (slot,id,file_sz) tuples; serializer groups by slot.
    storages: []const StorageEntry,
    /// versioned_epoch_stakes: per-epoch frozen vote-account stake tables, the
    /// REAL bank epoch_stakes (from AccountsDb.epoch_stakes). Defaults EMPTY so
    /// the legacy/empty-epoch_stakes path stays byte-identical. When non-empty,
    /// `serializeManifest` emits each entry as the byte-exact reverse of
    /// `readVersionedEpochStakesVecCapturing` (see `writeVersionedEpochStakes`).
    ///
    /// HONESTY (boot-completeness boundary): what is FULLY serialized vs stubbed
    /// per entry —
    ///   * vote_accounts (Vec<(vote_pubkey, stake, SolanaAccount)>): vote_pubkey
    ///     + stake are REAL; the SolanaAccount data is a SYNTHESIZED-minimal V4
    ///     (disc=3) vote blob carrying node_pubkey at data[4..36] and
    ///     commission_bps at data[132..134] (owner = Vote program). The FULL
    ///     frozen VoteState bytes are NOT retained by EpochStakesEntry (the
    ///     reader discarded them) → cannot be reproduced.
    ///   * total_stake (u64): REAL (sum of this epoch's vote-account stakes).
    ///   * node_id_to_vote_accounts (Map<node, (Vec<vote>, node_stake)>): REAL,
    ///     reconstructed by grouping vote accounts by their captured node_pubkey
    ///     (node_stake = sum of that node's vote-account stakes). This is the
    ///     leader-schedule input.
    ///   * stake_delegations / stake_history: STUBBED EMPTY (not in source).
    ///   * epoch_authorized_voters: STUBBED EMPTY (not in source).
    /// ⇒ The snapshot carries the LEADER-SCHEDULE SUBSET (staked node → vote
    ///    accounts → stake + total_stake), NOT full epoch_stakes. status_cache
    ///    and full Stakes-delegations remain stubbed.
    epoch_stakes: []const EpochStakesEntry = &[_]EpochStakesEntry{},
};

/// Vote program id (base58 `Vote111111111111111111111111111111111111111`).
/// Set as the synthesized vote-account owner for boot-realism in the
/// versioned_epoch_stakes serializer. (Bytes = "Vote" + padding.)
const VOTE_PROGRAM_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

/// Serialize the ExtraFields `versioned_epoch_stakes` Vec — the byte-exact
/// REVERSE of `readVersionedEpochStakesVecCapturing`. Emits:
///
///   vecLen(count)
///   per entry:
///     u64  epoch
///     u32  variant_tag = 0 (`Current`)            ← Bincode enum tag (u32 LE)
///     ── DeserializableStakes<Stake> ──
///     vote_accounts: Vec<(Pubkey, u64 stake, SolanaAccount)>
///       vecLen(va_count)
///       per vote account:
///         [32] vote_pubkey
///         u64  stake
///         SolanaAccount: u64 lamports, Vec<u8> data, [32] owner, u8 exec, u64 rent_epoch
///           data = SYNTHESIZED minimal V4 vote blob (≥134 bytes):
///             data[0..4]   = disc 3 (V4) LE   → reader's commission path
///             data[4..36]  = node_pubkey      → reader captures node_pubkey
///             data[36..132]= zero pad
///             data[132..134]= commission_bps LE → reader captures commission
///           owner = Vote program id; exec=false; rent_epoch=0.
///     stake_delegations: Vec<(Pubkey, Stake[72B])>  → vecLen(0) STUB
///       u64 unused header (read AFTER the len, per Agave) = 0
///     u64  stakes.epoch (= entry epoch)
///     stake_history: Vec<(u64, Entry24)>             → vecLen(0) STUB
///     ── after DeserializableStakes ──
///     u64  total_stake (REAL: sum of vote-account stakes)
///     node_id_to_vote_accounts: Vec<(Pubkey node, (Vec<Pubkey vote>, u64 node_stake))>
///       (REAL: grouped by captured node_pubkey, node_stake = sum of its votes)
///     epoch_authorized_voters: Vec<(Pubkey, Pubkey)>  → vecLen(0) STUB
///
/// REAL: vote_pubkey, stake, node_pubkey, commission_bps, total_stake,
/// node_id_to_vote_accounts. STUBBED: full VoteState bytes, stake_delegations,
/// stake_history, epoch_authorized_voters. ⇒ leader-schedule subset, NOT full
/// epoch_stakes (see ManifestWriteFields.epoch_stakes).
fn writeVersionedEpochStakes(
    s: *ManifestSerializer,
    allocator: std.mem.Allocator,
    epoch_stakes: []const EpochStakesEntry,
) !void {
    try s.vecLen(epoch_stakes.len);
    for (epoch_stakes) |entry| {
        try s.u64w(entry.epoch);
        try s.u32w(0); // variant_tag: `Current`

        const vas = entry.vote_account_stakes;
        const node_pks = entry.node_pubkeys;
        const comm_bps = entry.commission_bps;

        // vote_accounts: Vec<(Pubkey, u64, SolanaAccount)>
        try s.vecLen(vas.len);
        var total_stake: u64 = 0;
        for (vas, 0..) |va, i| {
            try s.bytesw(&va.vote_pubkey); // [32] vote_pubkey
            try s.u64w(va.stake); // u64 stake
            total_stake += va.stake;
            // SolanaAccount: synthesized minimal V4 vote blob.
            const node_pk: [32]u8 = if (i < node_pks.len) node_pks[i] else [_]u8{0} ** 32;
            const bps: u16 = if (i < comm_bps.len) comm_bps[i] else 0;
            try s.u64w(0); // lamports (boot-irrelevant; reader skips)
            // data: Vec<u8> — 134-byte minimal V4 vote account.
            const data_len: u64 = 134;
            try s.vecLen(data_len);
            try s.u32w(3); // disc = V4 (so reader reads commission_bps @ [132..134])
            try s.bytesw(&node_pk); // data[4..36] = node_pubkey
            try s.zeros(132 - 36); // data[36..132] = zero pad
            var bps_b: [2]u8 = undefined;
            std.mem.writeInt(u16, &bps_b, bps, .little);
            try s.bytesw(&bps_b); // data[132..134] = commission_bps LE
            try s.bytesw(&VOTE_PROGRAM_ID); // [32] owner
            try s.u8w(0); // executable: bool
            try s.u64w(0); // rent_epoch: u64
        }

        // stake_delegations: Vec<(Pubkey, Stake[72B])> — STUB empty.
        try s.vecLen(0); // count
        try s.u64w(0); // unused: u64 header (read AFTER the len, per Agave)
        try s.u64w(entry.epoch); // stakes.epoch
        try s.vecLen(0); // stake_history: empty

        // after DeserializableStakes:
        try s.u64w(total_stake); // total_stake (REAL)

        // node_id_to_vote_accounts: group vote accounts by node_pubkey.
        // REAL: a leader-schedule generator needs node → (vote accounts, stake).
        {
            var nodes = std.ArrayListUnmanaged([32]u8){};
            defer nodes.deinit(allocator);
            // Distinct node order (preserving first-seen).
            for (vas, 0..) |_, i| {
                const node_pk: [32]u8 = if (i < node_pks.len) node_pks[i] else [_]u8{0} ** 32;
                var seen = false;
                for (nodes.items) |n| {
                    if (std.mem.eql(u8, &n, &node_pk)) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) try nodes.append(allocator, node_pk);
            }
            try s.vecLen(nodes.items.len);
            for (nodes.items) |node_pk| {
                try s.bytesw(&node_pk); // node Pubkey
                // inner: (Vec<Pubkey vote>, u64 node_stake)
                var inner_count: u64 = 0;
                var node_stake: u64 = 0;
                for (vas, 0..) |va, i| {
                    const this_node: [32]u8 = if (i < node_pks.len) node_pks[i] else [_]u8{0} ** 32;
                    if (std.mem.eql(u8, &this_node, &node_pk)) {
                        inner_count += 1;
                        node_stake += va.stake;
                    }
                }
                try s.vecLen(inner_count); // Vec<Pubkey> length
                for (vas, 0..) |va, i| {
                    const this_node: [32]u8 = if (i < node_pks.len) node_pks[i] else [_]u8{0} ** 32;
                    if (std.mem.eql(u8, &this_node, &node_pk)) {
                        try s.bytesw(&va.vote_pubkey);
                    }
                }
                try s.u64w(node_stake); // node total_stake
            }
        }

        // epoch_authorized_voters: Vec<(Pubkey, Pubkey)> — STUB empty.
        try s.vecLen(0);
    }
}

/// Serialize a snapshot bank manifest to bincode bytes — the EXACT REVERSE of
/// `parseManifestFromBytes`. Caller owns the returned slice (free with
/// `allocator.free`). See ManifestWriteFields for the field/honesty mapping.
///
/// The emitted byte stream ends EXACTLY after the ExtraFields block_id Option
/// byte (no trailing padding) so the reader's canonical forward-parser
/// (`readLtHashAndBlockIdForward`, which requires `cur.pos == cur.data.len`)
/// hits instead of the defensive tail-seek fallback.
pub fn serializeManifest(
    allocator: std.mem.Allocator,
    f: ManifestWriteFields,
) ![]u8 {
    var s = ManifestSerializer.init(allocator);
    errdefer s.deinit();

    // ── BANK SECTION (reverse of skipBank) ──────────────────────────────────
    // 1. BlockhashQueue: last_hash_index(u64), Option<Hash> last_hash,
    //    ages: Vec<(Hash(32), HashAge(24))>, max_age(u64). (parseBlockhashQueue)
    try s.u64w(0); // last_hash_index
    try s.optHash(f.last_blockhash); // last_hash: Option<Hash>
    try s.vecLen(0); // ages: empty Vec
    try s.u64w(0); // max_age

    // 2. ancestors: Vec<(u64,u64)> — empty (skipVec skipSlotPair).
    try s.vecLen(0);

    // 3. bank_hash [32]  (READ, not skipped, by skipBank).
    try s.bytesw(&f.bank_hash);
    // 4. parent_hash [32]  (skipHash).
    try s.bytesw(&f.parent_hash);
    // 5. parent_slot: u64.
    try s.u64w(f.parent_slot);
    // 6. hard_forks: Vec<(u64,u64)> — empty (parseHardForks).
    try s.vecLen(0);
    // 7. transaction_count, tick_height, signature_count.
    //    signature_count seeds the reloaded root bank's FIRST per-slot
    //    FeeRateGovernor.newDerived — MUST be the real value (read at parse :688).
    try s.u64w(0);
    try s.u64w(0);
    try s.u64w(if (f.signature_count) |sc| sc else 0);
    // 8. capitalization.
    try s.u64w(f.capitalization);
    // 9. max_tick_height.
    try s.u64w(0);
    // 10. hashes_per_tick: Option<u64>.
    try s.optU64(f.hashes_per_tick);
    // 11. ticks_per_slot: u64.
    try s.u64w(f.ticks_per_slot);
    // 12. ns_per_slot: u128(16), genesis_creation_time(u64), slots_per_year(f64),
    //     accounts_data_len(u64), slot(u64), epoch(u64).
    try s.u128w(0); // ns_per_slot
    try s.u64w(0); // genesis_creation_time
    try s.f64w(0); // slots_per_year
    try s.u64w(0); // accounts_data_len
    try s.u64w(f.slot); // slot
    try s.u64w(f.epoch); // epoch
    // 13. block_height: u64.
    try s.u64w(f.block_height);
    // 14. collector_id: Pubkey(32).
    try s.zeros(32);
    // 15. collector_fees(u64), fee_calculator(u64).
    //     fee_calculator = the bank's CURRENT lamports_per_signature; the read side
    //     (:704) seeds gov.lamports_per_signature from it.
    try s.u64w(0); // collector_fees
    // 16. fee_calculator + fee_rate_governor: 4×u64 + burn_pct u8 = 33 bytes.
    //     These drive the per-slot RecentBlockhashes lamports_per_signature on the
    //     reloaded root bank (bank.zig:1571-1573). Wire order = readFeeRateGovernor
    //     (:805): target_lps, target_sps, min_lps, max_lps, burn_percent.
    if (f.fee_rate_governor) |g| {
        try s.u64w(g.lamports_per_signature); // fee_calculator
        try s.u64w(g.target_lamports_per_signature);
        try s.u64w(g.target_signatures_per_slot);
        try s.u64w(g.min_lamports_per_signature);
        try s.u64w(g.max_lamports_per_signature);
        try s.u8w(g.burn_percent);
    } else {
        try s.u64w(0); // fee_calculator
        try s.zeros(33); // fee_rate_governor (default)
    }
    // 17. collected_rent: u64.
    try s.u64w(0);
    // 18. rent_collector: epoch(u64) + epoch_schedule(33) + slots_per_year(f64) +
    //     rent(17) (skipRentCollector).
    try s.u64w(0); // rent_collector.epoch
    try s.zeros(33); // epoch_schedule
    try s.f64w(0); // slots_per_year
    try s.zeros(17); // rent
    // 19. epoch_schedule: 33 bytes (skipEpochSchedule).
    try s.zeros(33);
    // 20. inflation: 6×f64 = 48 bytes (skipInflation).
    try s.zeros(48);
    // 21. Stakes (readStakesCapturingVoteAccounts):
    //     vote_accounts: Map<Pubkey,(u64,SolanaAccount)> — empty.
    //     stake_delegations: Map<Pubkey,Delegation> = u64 len + u64 unused + ...
    //     epoch: u64. stake_history: Vec<(u64,Entry24)> — empty.
    try s.vecLen(0); // vote_accounts: empty
    try s.vecLen(0); // stake_delegations: empty len
    try s.u64w(0); // stake_delegations "unused: u64" header (read AFTER len)
    try s.u64w(0); // stakes.epoch
    try s.vecLen(0); // stake_history: empty
    // 22. unused_accounts: Vec<Pubkey>, Vec<Pubkey>, Vec<(Pubkey,u64)> — all empty.
    try s.vecLen(0);
    try s.vecLen(0);
    try s.vecLen(0);
    // 23. epoch_stakes (bank section): HashMap<Epoch,EpochStakes> — empty
    //     (skipVec skipEpochStakesPair).
    try s.vecLen(0);
    // 24. is_delta: bool.
    try s.u8w(0);

    // ── ACCOUNTS-DB STORAGES (reverse of readStorages) ──────────────────────
    // storages: Vec<SnapshotSlotAccVecs> = Vec<(slot, Vec<(id, file_sz)>)>.
    // Group the flat StorageEntry list by slot, preserving first-seen order.
    {
        // Count distinct slots (preserving order) and emit grouped.
        var slot_order = std.ArrayListUnmanaged(u64){};
        defer slot_order.deinit(allocator);
        for (f.storages) |e| {
            var seen = false;
            for (slot_order.items) |sl| {
                if (sl == e.slot) {
                    seen = true;
                    break;
                }
            }
            if (!seen) try slot_order.append(allocator, e.slot);
        }
        try s.vecLen(slot_order.items.len);
        for (slot_order.items) |sl| {
            try s.u64w(sl); // slot
            // account_vecs: Vec<(id, file_sz)>
            var n: u64 = 0;
            for (f.storages) |e| {
                if (e.slot == sl) n += 1;
            }
            try s.vecLen(n);
            for (f.storages) |e| {
                if (e.slot == sl) {
                    try s.u64w(e.id);
                    try s.u64w(e.file_sz);
                }
            }
        }
    }

    // ── ACCOUNTS-DB FIELDS TAIL (reverse of the prefix of
    //    readVersionedEpochStakesFromExtraFields) ───────────────────────────
    // write_version(u64) + slot(u64) + BankHashInfo(104B) +
    // historical_roots: Vec<Slot> + historical_roots_with_hash: Vec<(Slot,Hash)>.
    try s.u64w(0); // unused write_version
    try s.u64w(f.slot); // slot
    try s.zeros(104); // BankHashInfo (content skipped by reader)
    try s.vecLen(0); // historical_roots: empty
    try s.vecLen(0); // historical_roots_with_hash: empty

    // ── EXTRA FIELDS (reverse of the ExtraFields portion) ───────────────────
    // 1. lamports_per_signature: u64.
    try s.u64w(0);
    // 2. Option<UnusedIncrementalSnapshotPersistence>: None.
    try s.u8w(0);
    // 3. Option<Hash> (unused_epoch_accounts_hash): None.
    try s.u8w(0);
    // 4. versioned_epoch_stakes: Vec<(u64,DeserializableVersionedEpochStakes)>.
    //    Empty when f.epoch_stakes is empty (byte-identical to the legacy path);
    //    otherwise the byte-exact reverse of readVersionedEpochStakesVecCapturing.
    try writeVersionedEpochStakes(&s, allocator, f.epoch_stakes);
    // 5. Option<accounts_lt_hash = [u16;1024]> (2048 bytes): Some — the REAL lthash.
    try s.u8w(1);
    try s.bytesw(&f.accounts_lt_hash);
    // 6. Option<Hash> block_id: Some/None. MUST be the final byte(s) — the
    //    forward-parser asserts cursor == EOF immediately after.
    try s.optHash(f.block_id);

    return try s.buf.toOwnedSlice(allocator);
}

/// Write the serialized manifest to `<snapshot_dir>/snapshots/<slot>/<slot>`.
/// The parent directories must already exist (saveSnapshot makes them). Returns
/// the number of bytes written.
pub fn writeManifestFile(
    allocator: std.mem.Allocator,
    snapshot_dir: []const u8,
    f: ManifestWriteFields,
) !usize {
    const bytes = try serializeManifest(allocator, f);
    defer allocator.free(bytes);

    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/snapshots/{d}/{d}", .{
        snapshot_dir, f.slot, f.slot,
    });
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
    return bytes.len;
}

/// Write a valid EMPTY status-cache bincode artifact to
/// `<snapshot_dir>/snapshots/status_cache`.
///
/// v1 STUB (documented): Agave's status cache serializes as
/// `Vec<SlotDelta>` where SlotDelta = (slot: u64, is_root: bool,
/// statuses: HashMap<Hash, (u64, Vec<(KeySlice, Result)>)>). An EMPTY snapshot
/// has zero slot-deltas, which serializes as a single 8-byte LE zero (the Vec
/// length). This is a valid, loadable empty status cache — a fresh validator
/// rebuilds the cache from replay. NOT a full status-cache export (v2).
pub fn writeStatusCacheFile(
    snapshot_dir: []const u8,
) !void {
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/snapshots/status_cache", .{
        snapshot_dir,
    });
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    // Vec<SlotDelta> length = 0 (u64 LE).
    const empty_vec_len = [_]u8{0} ** 8;
    try file.writeAll(&empty_vec_len);
}
