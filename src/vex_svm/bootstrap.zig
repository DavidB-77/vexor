//! Vexor Validator Bootstrap — Production Startup Sequence
//!
//! Coordinates full startup: snapshot download → account loading → bank init → replay.
//!
//! Module dependencies:
//!   - vex_store: AccountsDb, SnapshotManager, ParallelSnapshotLoader
//!   - vex_svm: Bank, ReplayStage
//!   - vex_consensus: TowerBft (TODO)
//!   - core: Config, Keypair, Pubkey

const std = @import("std");
const Allocator = std.mem.Allocator;

const core = @import("core");
const vex_store = @import("vex_store");
const vex_crypto = @import("vex_crypto");
const bank_mod = @import("bank.zig");
const replay_stage_mod = @import("replay_stage.zig");
const types = @import("types.zig");

const Bank = bank_mod.Bank;
const Hash = types.Hash;
const LtHash = vex_crypto.LtHash;
const ReplayStage = replay_stage_mod.ReplayStage;
const AccountsDb = vex_store.accounts.AccountsDb;

pub const BootstrapPhase = enum {
    initializing,
    finding_snapshot,
    downloading_snapshot,
    loading_accounts,
    loading_tower,
    initializing_bank,
    initializing_replay,
    ready,
};

pub const BootstrapResult = struct {
    start_slot: u64,
    accounts_loaded: u64,
    total_lamports: u64,
    replay_stage: *ReplayStage,
    root_bank: *Bank,
    accounts_db: *AccountsDb,
    /// A3b snapshot-trust: the loaded snapshot's ARCHIVE checksum =
    /// BLAKE3(manifest accounts_lt_hash) == Agave SnapshotHash::new(checksum) ==
    /// the gossip `SnapshotHashes.full.hash` domain (same value the #39 full-only
    /// guard verifies). null for genesis / no manifest lt_hash. Consumed by the
    /// post-load/pre-vote snapshot-trust gate in main.zig (NOT bank_hash).
    base_archive_hash: ?[32]u8 = null,
};

pub const BootstrapConfig = struct {
    identity_path: []const u8,
    vote_account_path: ?[]const u8 = null,
    ledger_dir: []const u8 = "/mnt/ledger/vexor-testnet",
    accounts_dir: []const u8 = "/mnt/ramdisk/vexor-testnet",
    snapshots_dir: []const u8 = "/mnt/snapshots/vexor-testnet",
    rpc_url_override: ?[]const u8 = null,
    cluster: []const u8 = "testnet",
    enable_voting: bool = true,
    enable_parallel_snapshot: bool = true,
    parallel_snapshot_threads: u32 = 0,
    expected_shred_version: ?u16 = null,
    expected_genesis_hash: ?[]const u8 = null,
    force_fresh_snapshot: bool = false,
    /// Genesis mode: skip snapshot entirely, create empty slot-0 bank.
    /// Used for localnet (solana-test-validator) where no snapshot exists.
    genesis_mode: bool = false,
};

pub const ValidatorBootstrap = struct {
    allocator: Allocator,
    config: BootstrapConfig,
    identity: ?core.Keypair = null,
    accounts_db: ?*AccountsDb = null,
    current_phase: BootstrapPhase = .initializing,

    const Self = @This();

    pub fn init(allocator: Allocator, config: BootstrapConfig) !*Self {
        const self_ptr = try allocator.create(Self);
        self_ptr.* = .{
            .allocator = allocator,
            .config = config,
        };
        return self_ptr;
    }

    pub fn deinit(self: *Self) void {
        // NOTE: Do NOT deinit accounts_db here — it's passed to replay_stage
        // and must live for the entire validator lifetime.
        // if (self.accounts_db) |db| db.deinit();
        self.allocator.destroy(self);
    }

    pub fn bootstrap(self: *Self) !BootstrapResult {
        std.log.debug("[BOOTSTRAP] Starting bootstrap sequence\n", .{});

        // Phase 1: Load identity keypair (always required)
        self.current_phase = .initializing;
        try self.loadIdentity();
        std.log.debug("[BOOTSTRAP] Identity loaded\n", .{});

        // ── GENESIS MODE: skip snapshot entirely ─────────────────────────────
        if (self.config.genesis_mode) {
            return self.bootstrapGenesis();
        }

        // Phase 0: Clean stale state (skip if reusing existing snapshot)
        const reuse_snapshot = blk: {
            // Check if an extracted snapshot already exists
            var dir = if (std.fs.path.isAbsolute(self.config.snapshots_dir))
                std.fs.openDirAbsolute(self.config.snapshots_dir, .{ .iterate = true }) catch break :blk false
            else
                std.fs.cwd().openDir(self.config.snapshots_dir, .{ .iterate = true }) catch break :blk false;
            defer dir.close();
            var iter = dir.iterate();
            while (iter.next() catch null) |entry| {
                if (std.mem.startsWith(u8, entry.name, "extracted-")) {
                    break :blk true;
                }
            }
            break :blk false;
        };

        // carrier-16 replay-proof tooling: VEX_SNAPSHOT_OFFLINE pins the boot to
        // local snapshot material — cleanStaleState would DELETE the staged
        // incremental/full archives (it wipes extracted-*/incremental-*/
        // *.tar.zst) before the offline scan could find them; skip it entirely.
        if (std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null) {
            std.log.warn("[BOOTSTRAP-DIAG] VEX_SNAPSHOT_OFFLINE — skipping Phase 0 stale-state clean (local snapshot material preserved)", .{});
        } else if (reuse_snapshot and !self.config.force_fresh_snapshot) {
            std.log.debug("[BOOTSTRAP] Phase 0: Reusing existing snapshot (use --force-fresh-snapshot to re-download)\n", .{});
        } else {
            std.log.debug("[BOOTSTRAP] Phase 0: Cleaning stale state...\n", .{});
            try self.cleanStaleState();
        }

        // Phase 2: Initialize accounts database
        // vex-052: Instantiate AsyncIoManager so AccountsDb can use io_uring for
        // async account flush. AsyncIoManager.init has its own fallback — if
        // IoUring.init() fails (no io_uring support, missing perms, etc.) it
        // logs a warn and returns a manager with ring=null (effectively blocking
        // I/O). Either way the AccountsDb wireup is non-null so the optimization
        // paths actually execute. Validator lifetime; never deinit'd manually
        // (process-exit cleans up).
        self.current_phase = .loading_accounts;
        const async_mgr = vex_store.async_io.AsyncIoManager.init(self.allocator, .{}) catch |err| blk: {
            std.log.warn("[BOOTSTRAP] AsyncIoManager init failed ({s}), AccountsDb will use blocking I/O", .{@errorName(err)});
            break :blk null;
        };
        if (async_mgr) |m| {
            std.log.warn("[BOOTSTRAP] AsyncIoManager initialized — io_uring {s}", .{if (m.is_available) "ACTIVE" else "FALLBACK (blocking)"});
        }
        const accounts_db = try AccountsDb.init(self.allocator, self.config.accounts_dir, async_mgr);
        self.accounts_db = accounts_db;
        std.log.debug("[BOOTSTRAP] AccountsDb initialized at {s}\n", .{self.config.accounts_dir});

        // Phase 3: Discover, download, and extract snapshot (or reuse existing)
        self.current_phase = .finding_snapshot;
        var snapshot_slot: u64 = 0;
        var accounts_loaded: u64 = 0;
        var total_lamports: u64 = 0;
        var manifest_lthash: ?[2048]u8 = null;
        var manifest_bank_hash: ?[32]u8 = null;
        var manifest_block_height: u64 = 0;
        var manifest_capitalization: u64 = 0;
        // d28pp (2026-05-12): SIMD-0340 chained_block_id from snapshot tail.
        var manifest_block_id: ?[32]u8 = null;
        // carrier #16 (2026-06-12): real last_blockhash (NOT bank_hash) for root poh.
        var manifest_blockhash: ?[32]u8 = null;
        // verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
        // EFFECTIVE PoH cadence from the snapshot manifest, captured before the
        // loader scope ends. `manifest_hashes_per_tick` is the RAW Option already
        // collapsed via `orelse 0` (Agave `bank.hashes_per_tick().unwrap_or(0)`):
        // None → 0 → the verify_ticks hash-count checks are skipped.
        var manifest_hashes_per_tick: u64 = 0;
        var manifest_ticks_per_slot: u64 = 64;
        // CONSENSUS-CRITICAL (epoch-979 tip carrier): snapshot-restored fee-rate
        // governor + signature_count. Seed the root bank so the first per-slot
        // FeeRateGovernor.newDerived matches Agave rc.1. Defaults are inert: a
        // null governor leaves lps=0 (no per-slot adjustment), but on a real
        // testnet snapshot these are always populated (see [FEE-GOV-SEED] log).
        var manifest_fee_rate_governor: ?@import("blockhash_queue.zig").FeeRateGovernor = null;
        var manifest_signature_count: u64 = 0;

        const snap_dir = self.config.snapshots_dir;
        const extracted_dir = if (reuse_snapshot and !self.config.force_fresh_snapshot)
            try self.findExtractedSnapshot()
        else
            try self.downloadAndExtractSnapshot(snap_dir);

        // r72-perm-fix (2026-05-05): defensive chmod on the REUSE path.
        // Vexor's own extract (snapshot.zig:1059) already chmods after tar.
        // But the REUSE path skips extract — if the existing extracted-* dir
        // was populated by an operator running `tar -I zstd -xf` directly
        // (which preserves the tarball's stored mode 000 file perms), every
        // mmap() returns AccessDenied → 0/86.7M accounts loaded → 100%
        // bank_hash divergence. Idempotent + cheap (~30s on 33GB extract).
        // u+rwX = read+write for owner on files, +execute on dirs only.
        {
            const chmod_cmd = [_][]const u8{ "chmod", "-R", "u+rwX", extracted_dir };
            var chmod_child = std.process.Child.init(&chmod_cmd, std.heap.page_allocator);
            chmod_child.stdout_behavior = .Ignore;
            chmod_child.stderr_behavior = .Ignore;
            _ = chmod_child.spawnAndWait() catch |err| {
                std.log.warn("[BOOTSTRAP] r72-perm-fix chmod failed: {any} (continuing — load may fail)", .{err});
            };
        }

        // Phase 4: Load accounts from snapshot using parallel loader
        self.current_phase = .loading_accounts;
        {
            std.log.debug("[BOOTSTRAP] Loading snapshot with parallel loader...\n", .{});
            var loader = vex_store.parallel_snapshot.ParallelSnapshotLoader.init(self.allocator, .{
                .num_threads = if (self.config.parallel_snapshot_threads > 0)
                    @intCast(self.config.parallel_snapshot_threads)
                else
                    0, // auto = cpu_count - 1
                .verbose = true,
            });
            defer loader.deinit();

            const load_result = try loader.loadSnapshotParallel(extracted_dir, accounts_db);

            // Extract slot from directory name (extracted-SLOT)
            const dir_name = std.fs.path.basename(extracted_dir);
            if (std.mem.startsWith(u8, dir_name, "extracted-")) {
                snapshot_slot = std.fmt.parseInt(u64, dir_name["extracted-".len..], 10) catch 0;
            }
            accounts_loaded = load_result.accounts_loaded;
            total_lamports = load_result.lamports_total;
            manifest_lthash = loader.snapshot_lthash;
            manifest_bank_hash = loader.snapshot_bank_hash;
            manifest_block_height = loader.snapshot_block_height orelse 0;
            manifest_capitalization = loader.snapshot_capitalization orelse 0;
            manifest_block_id = loader.snapshot_block_id; // d28pp
            manifest_blockhash = loader.snapshot_blockhash; // carrier #16
            // verify_ticks: RAW Option → unwrap_or(0) (canonical Agave semantics).
            manifest_hashes_per_tick = loader.snapshot_hashes_per_tick_raw orelse 0;
            if (loader.snapshot_ticks_per_slot > 0) manifest_ticks_per_slot = loader.snapshot_ticks_per_slot;
            // CONSENSUS-CRITICAL (epoch-979): capture the snapshot fee-rate
            // governor + signature_count for the root bank seed.
            manifest_fee_rate_governor = loader.snapshot_fee_rate_governor;
            manifest_signature_count = loader.snapshot_signature_count orelse 0;

            // Transfer vote-stakes ownership to AccountsDb (survives loader.deinit).
            accounts_db.vote_account_stakes = loader.snapshot_vote_stakes;
            loader.snapshot_vote_stakes = &[_]@import("vex_store").snapshot_manifest.VoteAccountStake{};
            accounts_db.vote_frozen_data = loader.snapshot_vote_frozen;
            loader.snapshot_vote_frozen = &.{};
            std.log.debug("[BOOTSTRAP] Loaded {d} vote-account stakes into AccountsDb for SIMD-0001 Clock\n", .{
                accounts_db.vote_account_stakes.len,
            });

            // d16 (2026-05-10): transfer per-epoch frozen vote-account stake
            // tables (Agave's `epoch_stakes` blob) into AccountsDb. Used by
            // computeStakeWeightedClockEstimate at slot N to look up the
            // frozen stake table for `getEpoch(N)` instead of weighting
            // against the snapshot's much larger live `Stakes::vote_accounts`
            // (which contains every vote account ever known — ~15k vs the
            // current epoch's ~580 actually staked).
            accounts_db.epoch_stakes = loader.snapshot_epoch_stakes;
            loader.snapshot_epoch_stakes = &[_]@import("vex_store").snapshot_manifest.EpochStakesEntry{};
            std.log.debug("[BOOTSTRAP] Loaded {d} per-epoch stake tables into AccountsDb (Agave epoch_stakes mirror)\n", .{
                accounts_db.epoch_stakes.len,
            });

            // F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): transfer the snapshot
            // bank's hard-fork list into AccountsDb (survives loader.deinit;
            // freed in AccountsDb.deinit). Cluster-wide + immutable for replay,
            // so it rides on AccountsDb (same idiom as epoch_stakes) and every
            // Bank reads it via self.accounts_db.?.hard_forks. Drives F2
            // (bank-hash mixin) + F3 (LastRestartSlot). DORMANT on testnet.
            accounts_db.hard_forks = loader.snapshot_hard_forks;
            loader.snapshot_hard_forks = &[_]@import("vex_store").snapshot_manifest.HardFork{};
            std.log.debug("[BOOTSTRAP] Loaded {d} hard fork(s) into AccountsDb (F2/F3 source)\n", .{
                accounts_db.hard_forks.len,
            });

            // Seed top_votes so SIMD-0001 Clock estimation works from slot 1
            // of replay (no gap, no one-time lthash scar). Lives here (not
            // in accounts.zig) to keep the vex_store module free of a
            // cycle back into vex_svm/native/vote_state_serde.zig.
            seedTopVotesFromSnapshot(accounts_db);

            std.log.debug("[BOOTSTRAP] Loaded {d} accounts, {d} lamports from slot {d}\n", .{
                accounts_loaded, total_lamports, snapshot_slot,
            });

            // r71-fix-4 (2026-04-28): probe known program IDs after snapshot load to
            // confirm whether vex-061 BPF mutations=0 is "program not in AccountsDb"
            // or "BPF VM bug". Logs hit/miss for 6 program IDs that snapshot binary-grep
            // confirms ARE in the on-disk AppendVecs. If db.getAccount returns null for
            // any, the bug is in the indexing layer (likely full-vs-incremental manifest
            // overlap or AccountLocation slot-version handling).
            // r71-fix-4 (2026-04-28): probe pubkeys — bytes verified via Python
            // `base58.b58decode(b58str).hex()`, NOT hand-typed (replaces the
            // earlier probe with incorrect Router/ATA bytes).
            const probe_pks = [_]struct { name: []const u8, pk: [32]u8 }{
                .{ .name = "ATA           ", .pk = .{ 0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83, 0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59 } },
                .{ .name = "Router        ", .pk = .{ 0x06, 0x5a, 0xfb, 0x9d, 0xf9, 0xf6, 0x0d, 0x12, 0xf2, 0x09, 0x3a, 0x8e, 0x82, 0xb8, 0x54, 0xaf, 0xda, 0x8c, 0x5f, 0x86, 0x0a, 0xf0, 0x73, 0x8f, 0x5d, 0x13, 0x87, 0x15, 0x23, 0x33, 0xee, 0x2c } },
                .{ .name = "GJHtFqM9      ", .pk = .{ 0xe3, 0x4d, 0x44, 0xa4, 0x54, 0x26, 0xbd, 0x0c, 0xe4, 0x86, 0xc1, 0xed, 0xcc, 0xb2, 0xe3, 0x36, 0x08, 0x01, 0xb6, 0xd4, 0x26, 0x1d, 0xdc, 0x0f, 0x41, 0x3b, 0x11, 0xfe, 0xb2, 0xf3, 0x3f, 0x98 } },
                .{ .name = "DzvGET57T     ", .pk = .{ 0xc1, 0x22, 0x92, 0xce, 0xd5, 0x6f, 0x16, 0x6f, 0xa8, 0x3a, 0x6e, 0xfe, 0xc6, 0xa5, 0xd2, 0xe6, 0x18, 0x55, 0x65, 0xee, 0x18, 0xb3, 0x6c, 0x88, 0xfd, 0xe6, 0x21, 0x96, 0xf5, 0x09, 0x6b, 0x41 } },
                .{ .name = "Token (SPL)   ", .pk = .{ 0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9 } },
                .{ .name = "System        ", .pk = [_]u8{0} ** 32 },
                .{ .name = "Vote          ", .pk = .{ 0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3, 0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00 } },
                .{ .name = "ComputeBudget ", .pk = .{ 0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00 } },
            };
            std.log.debug("[BOOTSTRAP-PROBE] post-load layer-by-layer probe (idx | storage | full):\n", .{});
            for (probe_pks) |p| {
                const pk = core.Pubkey{ .data = p.pk };
                const idx_loc = accounts_db.index.get(&pk);
                const storage_acct = if (idx_loc) |loc| accounts_db.storage.readAccount(loc) else null;
                const full_acct = accounts_db._getRooted(&pk);
                std.log.debug("[BOOTSTRAP-PROBE]  {s} idx={s} storage={s} full={s}", .{
                    p.name,
                    if (idx_loc != null) "HIT" else "MISS",
                    if (storage_acct != null) "HIT" else "MISS",
                    if (full_acct != null) "HIT" else "MISS",
                });
                if (idx_loc) |loc| {
                    std.log.debug(" loc(slot={d} store_id={d} offset={d})", .{ loc.slot, loc.store_id, loc.offset });
                }
                std.log.debug("\n", .{});
            }
        }

        // CANONICAL GUARD (2026-06-03): verify the manifest-extracted base
        // accounts_lt_hash against the snapshot archive's authoritative
        // checksum (the incremental archive filename suffix == the bank's
        // accounts_lt_hash checksum at the snapshot slot). A wrong/null base
        // lattice silently corrupts EVERY replayed slot's bank_hash, and there
        // is NO recompute-from-accounts path — so on mismatch/missing we MUST
        // hard-fail the boot rather than proceed. This is the guard that would
        // have caught the manifest tail-seek off-by-one at boot.
        try self.verifyBaseLtHashAgainstArchive(snapshot_slot, manifest_lthash);

        // A3b snapshot-trust: capture the loaded snapshot's ARCHIVE checksum =
        // BLAKE3(accounts_lt_hash) — the SAME domain the #39 guard above verifies
        // against the archive filename suffix (Agave SnapshotHash::new(checksum),
        // checksum = blake3(lattice)) and the SAME domain a known-validator
        // advertises in its gossip SnapshotHashes.full.hash. Computed ONCE at boot
        // (negligible: one BLAKE3 over the 2048-byte lt). NOT bank_hash.
        var base_archive_hash: ?[32]u8 = null;
        if (manifest_lthash) |lt| {
            var h: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(&lt, &h, .{});
            base_archive_hash = h;
        }

        // Phase 5: Initialize root bank
        self.current_phase = .initializing_bank;
        var initial_lthash = LtHash.init();
        if (manifest_lthash) |lt| {
            // Copy manifest lthash bytes into LtHash struct (memcpy to avoid alignment issues)
            @memcpy(std.mem.asBytes(&initial_lthash.elements), &lt);
            std.log.debug("[BOOTSTRAP] LtHash loaded from manifest\n", .{});
        }

        // Use bank hash from snapshot manifest — critical for correct parent_hash chain.
        // Without this, every slot's bank hash is wrong because SHA256(parent || ...) uses wrong parent.
        const snapshot_hash = if (manifest_bank_hash) |bh|
            Hash{ .data = bh }
        else
            Hash{ .data = [_]u8{0} ** 32 };

        // carrier #16 @414812256 fix: the root bank's inherited poh_hash must be
        // the snapshot slot's LAST_BLOCKHASH (BlockhashQueue.last_hash), NOT its
        // bank_hash. The old r66 shortcut conflated them ("bank_hash IS the
        // last_blockhash") which is false — bank_hash = SHA256(parent||sigs||poh
        // ||lthash), last_blockhash = the last PoH entry hash. In LIVE replay
        // children inherit the real parent poh and everything works; but in a
        // close-boot directly onto the boundary, the boundary bank read the
        // root's poh_hash for EpochRewards.parent_blockhash and got the bank_hash
        // (da5f94fd) instead of the true blockhash (49cfff1b). Use the manifest's
        // captured last_blockhash; fall back to bank_hash only for older
        // snapshots that lacked the field.
        const root_poh_hash = if (manifest_blockhash) |lbh| Hash{ .data = lbh } else snapshot_hash;
        if (manifest_blockhash != null) {
            std.log.warn("[BOOTSTRAP] root poh_hash = manifest last_blockhash {x:0>2}{x:0>2}{x:0>2}{x:0>2}.. (carrier #16; distinct from bank_hash)", .{
                root_poh_hash.data[0], root_poh_hash.data[1], root_poh_hash.data[2], root_poh_hash.data[3],
            });
        }
        const root_bank = try Bank.init(
            self.allocator,
            snapshot_slot,
            null,
            snapshot_hash,
            initial_lthash,
            root_poh_hash,
        );
        root_bank.bank_hash = snapshot_hash;
        root_bank.block_height = manifest_block_height;
        root_bank.capitalization = manifest_capitalization;
        // CONSENSUS-CRITICAL (epoch-979 tip carrier): seed the root bank's
        // fee-rate governor + signature_count from the snapshot manifest. The
        // first post-boot child derives its governor via
        // FeeRateGovernor.newDerived(root.governor, root.signature_count); a
        // wrong seed re-introduces the RecentBlockhashes-sysvar divergence this
        // fix exists to close. signature_count NEVER feeds the root bank_hash
        // (that's loaded from the manifest, not recomputed); child banks reset
        // their own signature_count to 0.
        root_bank.signature_count = manifest_signature_count;
        if (manifest_fee_rate_governor) |g| {
            root_bank.fee_rate_governor = g;
            std.log.info(
                "[FEE-GOV-SEED] slot={d} lamports_per_signature={d} target_lamports_per_signature={d} target_signatures_per_slot={d} min_lps={d} max_lps={d} burn_percent={d} signature_count={d}",
                .{
                    snapshot_slot,
                    g.lamports_per_signature,
                    g.target_lamports_per_signature,
                    g.target_signatures_per_slot,
                    g.min_lamports_per_signature,
                    g.max_lamports_per_signature,
                    g.burn_percent,
                    manifest_signature_count,
                },
            );
        } else {
            std.log.warn(
                "[FEE-GOV-SEED] slot={d} manifest had NO fee_rate_governor — root governor left default (lps=0); per-slot derivation inert until populated",
                .{snapshot_slot},
            );
        }
        // verify_ticks: stamp the EFFECTIVE PoH cadence onto the root bank so
        // child banks (and any direct readers) have the manifest values. Cheap
        // unconditional writes; only READ behind the comptime verify_ticks gate.
        root_bank.hashes_per_tick = manifest_hashes_per_tick;
        root_bank.ticks_per_slot = manifest_ticks_per_slot;
        // d28pp (2026-05-12): seed canonical SIMD-0340 block_id from snapshot
        // tail. Replaces d28oo's first-shred adoption fallback for the
        // snapshot-anchor case. The snapshot is created at a ROOTED slot
        // (cluster-consensused), so embedded block_id IS the cluster-canonical
        // last-shred merkle root. Now ALL child slots can be validated against
        // a true cluster reference from slot anchor+1 onward instead of
        // adopting whatever leader sent the first shred.
        if (manifest_block_id) |bid| {
            root_bank.block_id = bid;
            root_bank.block_id_source = .manifest;
            const bid8: [8]u8 = bid[0..8].*;
            std.log.warn("[BOOTSTRAP] ✅ root_bank.block_id seeded from snapshot manifest: first8={any} (SIMD-0340 canonical reference)", .{bid8});
        } else {
            std.log.warn("[BOOTSTRAP] ⚠️  manifest had no block_id (older format) — falling back to d28oo first-shred adoption at slot anchor+1", .{});
        }

        if (manifest_bank_hash != null) {
            std.log.debug("[BOOTSTRAP] Root bank hash from manifest: {x:0>2}{x:0>2}{x:0>2}{x:0>2}.. block_height={d} capitalization={d}\n", .{
                snapshot_hash.data[0], snapshot_hash.data[1], snapshot_hash.data[2], snapshot_hash.data[3],
                manifest_block_height, manifest_capitalization,
            });
        } else {
            std.log.debug("[BOOTSTRAP] WARNING: No bank hash in manifest — parent hash chain will be wrong!\n", .{});
        }
        std.log.debug("[BOOTSTRAP] Root bank initialized at slot {d}\n", .{root_bank.slot});

        // r45-C (2026-04-27): seed root bank's RecentBlockhashes queue from snapshot.
        //
        // Pre-r45-C, Bank.init at bank.zig:423 sets `recent_blockhashes = .{}` (empty).
        // r38 added inheritance for child banks at replay_stage.zig:1255 but the ROOT bank
        // from snapshot stayed with count=0 — the queue self-fills only via per-slot push
        // at bank.zig:794-797, taking ~150 slots to reach the canonical depth. Until then
        // every replayed slot holds a partial RBH vs Agave's 150 → ~6008 bytes/slot of RBH
        // sysvar byte-divergence (per r37-diag verdict).
        //
        // This is the snapshot-side parser the r37-diag verdict design called for but
        // never shipped. Inverse of bank.zig:865-902 serialization:
        //   layout: count:u64-LE @0 + 150 entries @8 (each: blockhash[32] + lps:u64-LE)
        //   ordering: newest-first in serialized form, oldest-first in queue.buffer
        const RBH_PUBKEY_BYTES = [_]u8{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
            0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
            0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
            0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
        };
        const rbh_pk = core.Pubkey{ .data = RBH_PUBKEY_BYTES };
        var seeded_count: u64 = 0;
        if (accounts_db._getRooted(&rbh_pk)) |rbh_acct| {
            const data = rbh_acct.data;
            if (data.len >= 8) {
                const stored_count = std.mem.readInt(u64, data[0..8], .little);
                const max_entries: u64 = 150;
                const usable_count = if (stored_count > max_entries) max_entries else stored_count;
                if (data.len >= 8 + usable_count * 40) {
                    // Push entries in reverse iteration order (serialized is newest-first;
                    // queue.buffer wants oldest-first). Equivalent: read entry index
                    // (usable_count - 1) first → ... → entry 0 last.
                    var i: u64 = usable_count;
                    while (i > 0) {
                        i -= 1;
                        const off: usize = 8 + i * 40;
                        var bh_data: [32]u8 = undefined;
                        @memcpy(&bh_data, data[off..][0..32]);
                        const lps = std.mem.readInt(u64, data[off + 32 ..][0..8], .little);
                        root_bank.recent_blockhashes.push(.{
                            .blockhash = Hash{ .data = bh_data },
                            .lamports_per_signature = lps,
                        });
                        seeded_count += 1;
                    }
                }
            }
            std.log.debug("[BOOTSTRAP] r45-C: seeded RecentBlockhashes from snapshot, count={d} (stored data_len={d})\n", .{
                seeded_count, data.len,
            });
        } else {
            std.log.debug("[BOOTSTRAP] r45-C WARNING: RBH_PUBKEY account not found in snapshot — root bank queue starts empty (will self-fill ~150 slots)\n", .{});
        }

        // Phase 6: Initialize replay stage
        self.current_phase = .initializing_replay;
        const identity_pubkey = if (self.identity) |id| id.public else core.Pubkey{ .data = [_]u8{0} ** 32 };
        const replay = try ReplayStage.init(self.allocator, identity_pubkey);
        std.log.debug("[BOOTSTRAP] Replay stage initialized\n", .{});
        // verify_ticks: install the EFFECTIVE PoH cadence from the snapshot
        // manifest. Reachable in replayEntriesInternal via the per-bank fields
        // stamped in acquireBank. No-op when verify_ticks is .off.
        replay.setPohParams(manifest_hashes_per_tick, manifest_ticks_per_slot);

        // Phase 7: Ready
        self.current_phase = .ready;
        std.log.debug("[BOOTSTRAP] ✅ Bootstrap complete! Ready for replay.\n", .{});

        return BootstrapResult{
            .start_slot = snapshot_slot,
            .accounts_loaded = accounts_loaded,
            .total_lamports = total_lamports,
            .replay_stage = replay,
            .root_bank = root_bank,
            .accounts_db = accounts_db,
            .base_archive_hash = base_archive_hash,
        };
    }

    fn loadIdentity(self: *Self) !void {
        self.identity = try loadKeypairFromFile(self.allocator, self.config.identity_path);
    }

    /// Genesis mode bootstrap — no snapshot, creates empty slot-0 bank.
    /// Used for localnet (solana-test-validator) which starts at slot 0.
    fn bootstrapGenesis(self: *Self) !BootstrapResult {
        std.log.debug("[BOOTSTRAP] GENESIS MODE — creating empty root bank at slot 0\n", .{});

        // Create working directories
        for (&[_][]const u8{ self.config.accounts_dir, self.config.ledger_dir, self.config.snapshots_dir }) |dir_path| {
            if (std.fs.path.isAbsolute(dir_path)) {
                std.fs.makeDirAbsolute(dir_path) catch {};
            } else {
                std.fs.cwd().makePath(dir_path) catch {};
            }
        }

        // Initialize empty AccountsDb (genesis-mode path)
        // vex-052: Same wireup as the snapshot path above — instantiate
        // AsyncIoManager and pass it. Internal fallback handles io_uring failure.
        self.current_phase = .loading_accounts;
        const async_mgr_genesis = vex_store.async_io.AsyncIoManager.init(self.allocator, .{}) catch |err| blk: {
            std.log.warn("[BOOTSTRAP-GENESIS] AsyncIoManager init failed ({s}), using blocking I/O", .{@errorName(err)});
            break :blk null;
        };
        const accounts_db = try AccountsDb.init(self.allocator, self.config.accounts_dir, async_mgr_genesis);
        self.accounts_db = accounts_db;
        std.log.debug("[BOOTSTRAP] Empty AccountsDb initialized at {s}\n", .{self.config.accounts_dir});

        // Fetch epoch schedule from test-validator RPC
        // Critical: test-validator uses 32-slot epochs, not 432000-slot epochs.
        var epoch_schedule = bank_mod.EpochSchedule.DEFAULT;
        const rpc_url = self.config.rpc_url_override orelse "http://localhost:8799";
        epoch_schedule = fetchEpochSchedule(self.allocator, rpc_url) catch |err| blk: {
            std.log.debug("[BOOTSTRAP] WARNING: Failed to fetch epoch schedule from {s}: {any}, using defaults\n", .{ rpc_url, err });
            break :blk epoch_schedule;
        };
        std.log.debug("[BOOTSTRAP] EpochSchedule: slots_per_epoch={d} warmup={}\n", .{ epoch_schedule.slots_per_epoch, epoch_schedule.warmup });

        // Create root bank at slot 0 with zeroed hashes
        self.current_phase = .initializing_bank;
        const root_bank = try Bank.init(
            self.allocator,
            0, // slot 0
            null, // no parent
            Hash{ .data = [_]u8{0} ** 32 }, // zeroed parent hash
            LtHash.init(),
            Hash{ .data = [_]u8{0} ** 32 }, // r66: zero parent_poh_hash for genesis
        );
        root_bank.bank_hash = Hash{ .data = [_]u8{0} ** 32 };
        root_bank.block_height = 0;
        root_bank.capitalization = 0;
        root_bank.epoch_schedule = epoch_schedule;
        std.log.debug("[BOOTSTRAP] Genesis root bank created at slot 0\n", .{});

        // Initialize replay stage
        self.current_phase = .initializing_replay;
        const identity_pubkey = if (self.identity) |id| id.public else core.Pubkey{ .data = [_]u8{0} ** 32 };
        const replay = try ReplayStage.init(self.allocator, identity_pubkey);

        // Enable RPC account fallback so tx execution can resolve accounts lazily
        replay.genesis_rpc_fallback = self.config.rpc_url_override;

        self.current_phase = .ready;
        std.log.debug("[BOOTSTRAP] Genesis bootstrap complete — ready for replay from slot 0\n", .{});

        return BootstrapResult{
            .start_slot = 0,
            .accounts_loaded = 0,
            .total_lamports = 0,
            .replay_stage = replay,
            .root_bank = root_bank,
            .accounts_db = accounts_db,
        };
    }

    fn findExtractedSnapshot(self: *Self) ![]const u8 {
        var dir = try std.fs.cwd().openDir(self.config.snapshots_dir, .{ .iterate = true });
        defer dir.close();

        var best_slot: u64 = 0;
        var best_name: ?[]const u8 = null;

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, "extracted-")) {
                const slot_str = entry.name["extracted-".len..];
                const slot = std.fmt.parseInt(u64, slot_str, 10) catch continue;
                if (slot > best_slot) {
                    best_slot = slot;
                    if (best_name) |old| self.allocator.free(old);
                    best_name = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.config.snapshots_dir, entry.name });
                }
            }
        }

        return best_name orelse error.NoSnapshotFound;
    }

    /// Verify the manifest-extracted base accounts_lt_hash against the snapshot
    /// archive's authoritative checksum.
    ///
    /// With the accounts_lt_hash feature active (Agave 4.x), the incremental
    /// snapshot archive filename's hash suffix —
    /// `incremental-snapshot-<full>-<slot>-<HASH>.tar.zst` — IS the bank's
    /// accounts_lt_hash checksum at <slot> (verified against agave-ledger-tool:
    /// `bank frozen: <slot> … accounts_lt_hash checksum: <HASH>`). Comparing
    /// the BLAKE3 checksum of the loaded 2048-byte base lattice to that suffix
    /// is a free, authoritative guard. A mismatch means manifest extraction
    /// grabbed the wrong bytes, which silently corrupts every replayed slot's
    /// bank_hash. There is NO recompute-from-accounts path, so on mismatch or a
    /// null base we hard-fail the boot.
    ///
    /// FULL-ONLY-BOOT guard (task #39, 2026-06-22): the SAME check now also
    /// applies to a FULL archive `snapshot-<slot>-<HASH>.tar.zst`. Full-only is
    /// not an edge case — it is the live node's incremental-failure fallback
    /// (this file's discovery path falls to full-only when the incremental fetch
    /// fails or no local incremental exists). Canonical justification (Agave
    /// 4.1.0-rc.1, source-verified): `SnapshotHash::new(checksum)`
    /// (snapshots/src/snapshot_hash.rs) is the SINGLE constructor for BOTH the
    /// full and incremental filename hashes, and `checksum() = blake3(lattice)`
    /// (lattice-hash/src/lt_hash.rs:53) — so a full archive's `<HASH>` suffix IS
    /// BLAKE3(accounts_lt_hash at <slot>), identical derivation to the
    /// incremental. Proven byte-exact offline against a real full snapshot
    /// (`zig build test-manifest-lthash-verify`, extracted-415214213 → AmaHFX…MFiq
    /// MATCH), so it ships ON-by-default with no false-reject risk: a mismatch is
    /// real corruption and MUST hard-fail. Only when NEITHER an incremental nor a
    /// full archive matches the slot do we warn-and-proceed (no archive to verify
    /// against; the forward-parse structural check stands).
    fn verifyBaseLtHashAgainstArchive(self: *Self, snapshot_slot: u64, manifest_lthash: ?[2048]u8) !void {
        var dir = std.fs.cwd().openDir(self.config.snapshots_dir, .{ .iterate = true }) catch |e| {
            std.log.warn("[BOOTSTRAP] base lt_hash guard: cannot open snapshots dir ({}) — skipping verification", .{e});
            return;
        };
        defer dir.close();

        var slot_buf: [40]u8 = undefined;
        const needle = std.fmt.bufPrint(&slot_buf, "-{d}-", .{snapshot_slot}) catch return;
        var suffix_buf: [88]u8 = undefined;
        var suffix_len: usize = 0;
        var found = false;
        var archive_kind: []const u8 = "incremental";
        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            const n = entry.name;
            if (!std.mem.startsWith(u8, n, "incremental-snapshot-")) continue;
            if (!std.mem.endsWith(u8, n, ".tar.zst")) continue;
            const ndl_pos = std.mem.indexOf(u8, n, needle) orelse continue;
            const hs = ndl_pos + needle.len;
            const he = n.len - ".tar.zst".len;
            if (he <= hs or (he - hs) > suffix_buf.len) continue;
            @memcpy(suffix_buf[0 .. he - hs], n[hs..he]);
            suffix_len = he - hs;
            found = true;
            break;
        }

        // FULL-ONLY-BOOT guard (task #39): no incremental archive matched — this
        // is a full-only boot (or the incremental-fetch-failed fallback). Verify
        // against the FULL archive `snapshot-<slot>-<HASH>.tar.zst` whose suffix
        // is the SAME BLAKE3(accounts_lt_hash) checksum (canonical, proven — see
        // the doc comment above). `startsWith("snapshot-")` excludes
        // `incremental-snapshot-` (which starts with "incremental-"). In a
        // combined boot snapshot_slot==incremental_slot, which never matches a
        // full archive's `-<full_slot>-`, so this only fires on a genuine
        // full-only boot — it strictly ADDS a check, never weakens the existing one.
        if (!found) {
            var it_full = dir.iterate();
            while (it_full.next() catch null) |entry| {
                const n = entry.name;
                if (!std.mem.startsWith(u8, n, "snapshot-")) continue;
                if (!std.mem.endsWith(u8, n, ".tar.zst")) continue;
                const ndl_pos = std.mem.indexOf(u8, n, needle) orelse continue;
                const hs = ndl_pos + needle.len;
                const he = n.len - ".tar.zst".len;
                if (he <= hs or (he - hs) > suffix_buf.len) continue;
                @memcpy(suffix_buf[0 .. he - hs], n[hs..he]);
                suffix_len = he - hs;
                found = true;
                archive_kind = "full";
                break;
            }
        }

        if (!found) {
            std.log.warn("[BOOTSTRAP] base lt_hash guard: no incremental OR full archive for slot {d} — cannot verify base (forward-parse structural check stands)", .{snapshot_slot});
            return;
        }

        const expected_suffix = suffix_buf[0..suffix_len];
        var expected: [32]u8 = undefined;
        core.base58.decodeToBuf(expected_suffix, &expected) catch |e| {
            std.log.warn("[BOOTSTRAP] base lt_hash guard: archive suffix '{s}' not base58 ({}) — skipping", .{ expected_suffix, e });
            return;
        };

        const lt = manifest_lthash orelse {
            std.log.err("[BOOTSTRAP] ❌ FATAL: no accounts_lt_hash extracted from snapshot manifest, but {s}-archive checksum {s} exists. A null base = ZERO lattice = corrupt bank_hash on every slot, with no recompute path. Refusing to boot.", .{ archive_kind, expected_suffix });
            return error.SnapshotLtHashMissing;
        };
        var actual: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&lt, &actual, .{});
        if (!std.mem.eql(u8, &actual, &expected)) {
            std.log.err("[BOOTSTRAP] ❌ FATAL: base accounts_lt_hash MISMATCH vs {s} snapshot archive checksum {s} (slot {d}). Manifest extraction grabbed the wrong bytes; booting would corrupt every bank_hash. Refusing to boot.", .{ archive_kind, expected_suffix, snapshot_slot });
            return error.SnapshotLtHashMismatch;
        }
        std.log.warn("[BOOTSTRAP] ✅ base accounts_lt_hash verified against {s} snapshot archive checksum {s} (slot {d})", .{ archive_kind, expected_suffix, snapshot_slot });
    }

    /// Phase 0: Wipe all stale state so every boot is a fresh start.
    /// Clears accounts, ledger, and old extracted/archived snapshots.
    fn cleanStaleState(self: *Self) !void {
        const dirs_to_clean = [_]struct { path: []const u8, label: []const u8 }{
            .{ .path = self.config.accounts_dir, .label = "accounts" },
            .{ .path = self.config.ledger_dir, .label = "ledger" },
        };

        for (dirs_to_clean) |entry| {
            // Delete and recreate
            if (std.fs.path.isAbsolute(entry.path)) {
                std.fs.deleteTreeAbsolute(entry.path) catch {};
                std.fs.makeDirAbsolute(entry.path) catch {};
            } else {
                std.fs.cwd().deleteTree(entry.path) catch {};
                std.fs.cwd().makePath(entry.path) catch {};
            }
            std.log.debug("[BOOTSTRAP]   {s} cleared\n", .{entry.label});
        }

        // Clean extracted snapshots and archives from snapshots dir
        const snap_dir = if (std.fs.path.isAbsolute(self.config.snapshots_dir))
            std.fs.openDirAbsolute(self.config.snapshots_dir, .{ .iterate = true }) catch {
                std.fs.makeDirAbsolute(self.config.snapshots_dir) catch {};
                return;
            }
        else
            std.fs.cwd().openDir(self.config.snapshots_dir, .{ .iterate = true }) catch {
                std.fs.cwd().makePath(self.config.snapshots_dir) catch {};
                return;
            };

        var dir = snap_dir;
        defer dir.close();
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            const should_delete = std.mem.startsWith(u8, entry.name, "extracted-") or
                std.mem.startsWith(u8, entry.name, "incremental-") or
                std.mem.endsWith(u8, entry.name, ".tar.zst") or
                std.mem.endsWith(u8, entry.name, ".tar.bz2");
            if (should_delete) {
                if (entry.kind == .directory) {
                    dir.deleteTree(entry.name) catch {};
                } else {
                    dir.deleteFile(entry.name) catch {};
                }
            }
        }
        std.log.debug("[BOOTSTRAP]   snapshots cleaned\n", .{});
    }

    /// Phase 3: Discover snapshot from cluster, download, and extract.
    /// Returns the path to the extracted snapshot directory.
    fn downloadAndExtractSnapshot(self: *Self, snap_dir: []const u8) ![]const u8 {
        self.current_phase = .finding_snapshot;

        // carrier-16 replay-proof tooling (2026-06-12): VEX_SNAPSHOT_OFFLINE — if a
        // local `extracted-<slot>` dir already exists (with a snapshots/ manifest
        // subdir), boot from the HIGHEST one DIRECTLY and skip all cluster
        // discovery/download/extract. This lets a forensic boot start from a
        // create-snapshot of the parent-of-onset (e.g. extracted-414812255) so the
        // FIRST replayed slot is the carrier slot itself — ~3 min to verdict vs
        // ~20 replaying a 1000-slot incremental gap. A bare create-snapshot full is
        // self-contained (complete account state), so no incremental is needed.
        if (std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null) {
            var best_slot: u64 = 0;
            if (std.fs.openDirAbsolute(snap_dir, .{ .iterate = true })) |dir_const| {
                var dir = dir_const;
                defer dir.close();
                var it = dir.iterate();
                while (it.next() catch null) |entry| {
                    if (entry.kind != .directory) continue;
                    if (!std.mem.startsWith(u8, entry.name, "extracted-")) continue;
                    const slot = std.fmt.parseInt(u64, entry.name["extracted-".len..], 10) catch continue;
                    // require the manifest subdir so we never pick a half-extract
                    var sub = dir.openDir(entry.name, .{}) catch continue;
                    defer sub.close();
                    _ = sub.statFile("snapshots") catch continue;
                    if (slot > best_slot) best_slot = slot;
                }
            } else |_| {}
            if (best_slot != 0) {
                const local_dir = try std.fmt.allocPrint(self.allocator, "{s}/extracted-{d}", .{ snap_dir, best_slot });
                std.log.warn("[BOOTSTRAP-DIAG] VEX_SNAPSHOT_OFFLINE — booting DIRECTLY from local extracted-{d} (skipping cluster discovery/download)", .{best_slot});
                return local_dir;
            }
            std.log.warn("[BOOTSTRAP-DIAG] VEX_SNAPSHOT_OFFLINE — no local extracted-<slot> dir found; falling through to normal discovery", .{});
        }

        // Initialize snapshot manager with testnet RPC endpoints
        var sm = vex_store.snapshot.SnapshotManager.init(self.allocator, snap_dir);
        defer sm.deinit();

        // Add RPC endpoints — operator override(s) first, then cluster default.
        // A2: --rpc-url (config.rpc_url_override) is the primary operator escape
        // hatch — when the default cluster RPC is down (the api.testnet 503 that
        // stranded bootstrap on 2026-06-05), point Vexor at any healthy RPC.
        if (self.config.rpc_url_override) |url| {
            try sm.addRpcEndpoint(url); // RULE#1: hard-fails if url is oracle-node
        }

        // A1 multi-seed: VEXOR_SNAPSHOT_RPCS is an optional comma-separated list of
        // ADDITIONAL snapshot getClusterNodes seeds, so a single RPC outage is never
        // a single point of failure. Kept separate from rpc_url_override (which other
        // subsystems consume as ONE url). Seeds are duped (env buffer is transient)
        // and freed after sm is done; each passes the RULE#1 deny-list chokepoint.
        var extra_seed_storage = std.ArrayListUnmanaged([]u8){};
        // LIFO: declared after `defer sm.deinit()` ⇒ runs BEFORE it. sm.deinit frees
        // only the endpoint-slice headers, never the pointed-to bytes, so freeing the
        // duped seeds here (at function exit) is neither a double-free nor a UAF.
        defer {
            for (extra_seed_storage.items) |s| self.allocator.free(s);
            extra_seed_storage.deinit(self.allocator);
        }
        if (std.process.getEnvVarOwned(self.allocator, "VEXOR_SNAPSHOT_RPCS")) |list| {
            defer self.allocator.free(list);
            var it = std.mem.splitScalar(u8, list, ',');
            while (it.next()) |raw| {
                const trimmed = std.mem.trim(u8, raw, " \t\r\n");
                if (trimmed.len == 0) continue;
                const owned = try self.allocator.dupe(u8, trimmed);
                sm.addRpcEndpoint(owned) catch |e| {
                    self.allocator.free(owned);
                    if (e == error.DeniedRpcEndpoint) return e; // RULE#1: hard-fail boot
                    std.log.warn("[BOOTSTRAP] skipping bad VEXOR_SNAPSHOT_RPCS seed '{s}': {any}", .{ trimmed, e });
                    continue;
                };
                try extra_seed_storage.append(self.allocator, owned);
            }
        } else |_| {}

        // Always add the standard cluster RPC as the final fallback
        if (std.mem.eql(u8, self.config.cluster, "testnet")) {
            try sm.addRpcEndpoint("https://api.testnet.solana.com");
        } else if (std.mem.eql(u8, self.config.cluster, "devnet")) {
            try sm.addRpcEndpoint("https://api.devnet.solana.com");
        } else if (std.mem.eql(u8, self.config.cluster, "mainnet") or
            std.mem.eql(u8, self.config.cluster, "mainnet-beta"))
        {
            try sm.addRpcEndpoint("https://api.mainnet-beta.solana.com");
        }

        // Discover best snapshot pair (full + optional incremental)
        std.log.debug("[BOOTSTRAP] Discovering snapshots from cluster...\n", .{});
        const pair = (try sm.findBestSnapshotPair()) orelse {
            std.log.debug("[BOOTSTRAP] FATAL: No snapshot available from any cluster node\n", .{});
            return error.NoSnapshotFound;
        };

        std.log.debug("[BOOTSTRAP] Found full snapshot: slot {d}\n", .{pair.full.slot});
        if (pair.incremental) |inc| {
            std.log.debug("[BOOTSTRAP] Found incremental snapshot: slot {d} (base {d})\n", .{
                inc.slot, inc.base_slot orelse 0,
            });
        }

        // Download full snapshot
        self.current_phase = .downloading_snapshot;

        // Fix B (2026-05-05) — preserve-aware skip-download.
        // Check if cluster's chosen full-snapshot file already exists locally with sane
        // size (>100 MB). If yes AND its extracted-dir already exists with manifest, we
        // can skip the 5.1 GB download (~48 sec) + extract (~52 sec). This is the
        // dominant warm-reboot win — back-to-back deploys reuse the same cluster
        // snapshot until it rotates (~12 hr cadence per --full-snapshot-interval-slots).
        const full_local_path = try self.snapshotArchivePath(&sm, &pair.full, snap_dir);
        const full_extract_dir = try std.fmt.allocPrint(
            self.allocator,
            "{s}/extracted-{d}",
            .{ snap_dir, pair.full.slot },
        );

        const have_local_full = blk: {
            const stat = std.fs.cwd().statFile(full_local_path) catch break :blk false;
            if (stat.size < 100 * 1024 * 1024) break :blk false; // sanity: real fulls are GBs
            // Confirm extracted dir has a snapshots/ subdir (the manifest lives there)
            var dir = std.fs.openDirAbsolute(full_extract_dir, .{}) catch break :blk false;
            defer dir.close();
            _ = dir.statFile("snapshots") catch break :blk false;
            break :blk true;
        };

        if (have_local_full) {
            std.log.warn("[BOOTSTRAP-DIAG] Fix B: local full snapshot at slot {d} matches cluster's choice — skipping {d} byte download + extract", .{ pair.full.slot, @as(u64, @intCast(@max(0, pair.full.size_bytes))) });
        } else {
            std.log.debug("[BOOTSTRAP] Downloading full snapshot...\n", .{});
            sm.download(&pair.full, printDownloadProgress) catch |err| {
                std.log.debug("[BOOTSTRAP] Full snapshot download failed: {any}\n", .{err});
                return err;
            };

            // Extract full snapshot
            std.log.debug("[BOOTSTRAP] Extracting full snapshot to {s}...\n", .{full_extract_dir});
            sm.extract(
                full_local_path,
                full_extract_dir,
            ) catch |err| {
                std.log.debug("[BOOTSTRAP] Extraction failed: {any}\n", .{err});
                return err;
            };
        }

        // Download and extract incremental if available
        if (pair.incremental) |inc| {
            // carrier-16 replay-proof tooling (2026-06-12): VEX_SNAPSHOT_OFFLINE=1
            // pins the boot to LOCAL snapshot material. Without it, --bootstrap
            // ALWAYS tops up to the cluster's freshest incremental for the same
            // full — which silently replaced every pre-boundary forensic base
            // tonight (4 sabotaged replay-proof boots). Offline mode scans
            // snap_dir for the newest LOCAL incremental of this full and uses
            // it; if none, boots full-only. (The full itself is already served
            // locally by the Fix-B have_local_full path above when it matches
            // the cluster's choice; a non-matching local full still downloads —
            // acceptable for now, warned below.)
            if (std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null) {
                std.log.warn("[BOOTSTRAP-DIAG] VEX_SNAPSHOT_OFFLINE — skipping cluster incremental top-up (cluster offered slot {d}); scanning local material for full {d}", .{ inc.slot, pair.full.slot });
                var best_slot: u64 = 0;
                var best_name_buf: [512]u8 = undefined;
                var best_name_len: usize = 0;
                if (std.fs.openDirAbsolute(snap_dir, .{ .iterate = true })) |dir_const| {
                    var dir = dir_const;
                    defer dir.close();
                    var it = dir.iterate();
                    while (it.next() catch null) |entry| {
                        if (entry.kind != .file and entry.kind != .sym_link) continue;
                        const info = vex_store.snapshot.SnapshotInfo.fromFilename(entry.name) orelse continue;
                        if (!info.is_incremental) continue;
                        if ((info.base_slot orelse 0) != pair.full.slot) continue;
                        if (info.slot > best_slot and entry.name.len <= best_name_buf.len) {
                            best_slot = info.slot;
                            best_name_len = entry.name.len;
                            @memcpy(best_name_buf[0..entry.name.len], entry.name);
                        }
                    }
                } else |err| {
                    std.log.warn("[BOOTSTRAP-DIAG] OFFLINE: cannot scan {s}: {any} — booting full-only", .{ snap_dir, err });
                    return full_extract_dir;
                }
                if (best_slot == 0) {
                    std.log.warn("[BOOTSTRAP-DIAG] OFFLINE: no local incremental for full {d} — booting full-only", .{pair.full.slot});
                    return full_extract_dir;
                }
                const local_inc_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ snap_dir, best_name_buf[0..best_name_len] }) catch return full_extract_dir;
                std.log.warn("[BOOTSTRAP-DIAG] OFFLINE: using local incremental {s} (slot {d})", .{ best_name_buf[0..best_name_len], best_slot });
                sm.extract(local_inc_path, full_extract_dir) catch |err| {
                    std.log.warn("[BOOTSTRAP-DIAG] OFFLINE incremental extraction FAILED: {any} — falling back to full-only", .{err});
                    return full_extract_dir;
                };
                const off_inc_dir = std.fmt.allocPrint(self.allocator, "{s}/extracted-{d}", .{ snap_dir, best_slot }) catch return full_extract_dir;
                if (std.fs.path.isAbsolute(full_extract_dir)) {
                    std.fs.renameAbsolute(full_extract_dir, off_inc_dir) catch return full_extract_dir;
                } else {
                    std.fs.cwd().rename(full_extract_dir, off_inc_dir) catch return full_extract_dir;
                }
                self.allocator.free(full_extract_dir);
                return off_inc_dir;
            }
            std.log.warn("[BOOTSTRAP-DIAG] Downloading incremental snapshot (slot {d})...", .{inc.slot});

            // vex-030 (restored 2026-05-05): multi-peer incremental rotation.
            // Original peer's incremental URL is reliably stale by ~90s of full-download time
            // (cluster rotates incrementals every ~40s and DELETES rotated-past archives).
            // On failure, re-query getClusterNodes and try up to 4 other peers before
            // falling back to full-only. Pairs with the bf8bdc98 download guard:
            // guard catches HTTP 4xx/5xx + empty body → triggers this rotation.
            var active_inc: ?vex_store.snapshot.SnapshotInfo = null;

            // Helper: strip http(s):// prefix and path to get host:port
            const extractHost = struct {
                fn run(url: []const u8) []const u8 {
                    var h = url;
                    if (std.mem.startsWith(u8, h, "http://")) h = h[7..];
                    if (std.mem.startsWith(u8, h, "https://")) h = h[8..];
                    if (std.mem.indexOfScalar(u8, h, '/')) |s| h = h[0..s];
                    return h;
                }
            }.run;

            // Attempt 1: original peer.
            const orig_failed = blk: {
                sm.download(&inc, printDownloadProgress) catch {
                    const orig_host = extractHost(inc.download_url orelse "");
                    std.log.warn("[BOOTSTRAP-DIAG] Incremental download failed on peer {s} — rotating to alternates", .{orig_host});
                    break :blk true;
                };
                active_inc = inc;
                std.log.warn("[BOOTSTRAP-DIAG] Incremental download OK (original peer)", .{});
                break :blk false;
            };

            if (orig_failed) {
                const orig_host = extractHost(inc.download_url orelse "");
                const tried = [_][]const u8{orig_host};
                const disc_endpoint = if (sm.rpc_endpoints.items.len > 0)
                    sm.rpc_endpoints.items[0]
                else
                    "https://api.testnet.solana.com";

                const rotation_result = sm.findIncrementalAcrossPeers(disc_endpoint, pair.full.slot, &tried, 4) catch |err| blk: {
                    std.log.warn("[BOOTSTRAP-DIAG] Multi-peer rotation query failed: {any} — booting from full snapshot only", .{err});
                    break :blk null;
                };
                if (rotation_result) |cand| {
                    sm.download(&cand, printDownloadProgress) catch {
                        std.log.warn("[BOOTSTRAP-DIAG] Rotation peer download also failed — booting from full snapshot only", .{});
                        return full_extract_dir;
                    };
                    active_inc = cand;
                    const cand_host = extractHost(cand.download_url orelse "");
                    std.log.warn("[BOOTSTRAP-DIAG] ✅ Incremental loaded from rotation peer {s} (slot {d})", .{ cand_host, cand.slot });
                } else {
                    std.log.warn("[BOOTSTRAP-DIAG] All rotation peers exhausted — booting from full snapshot only", .{});
                    return full_extract_dir;
                }
            }

            const active = active_inc orelse return full_extract_dir;

            // Extract incremental ON TOP of the full extraction. On failure, RETURN
            // full_extract_dir (no rename) — matches archive-path-resolve failure handling.
            std.log.warn("[BOOTSTRAP-DIAG] Extracting incremental snapshot...", .{});
            const inc_path = self.snapshotArchivePath(&sm, &active, snap_dir) catch |err| {
                std.log.warn("[BOOTSTRAP-DIAG] Incremental archive path resolve FAILED: {any} — continuing with full only", .{err});
                return full_extract_dir;
            };
            sm.extract(inc_path, full_extract_dir) catch |err| {
                std.log.warn("[BOOTSTRAP-DIAG] Incremental extraction FAILED: {any} — falling back to full-only (skipping rename)", .{err});
                return full_extract_dir;
            };
            std.log.warn("[BOOTSTRAP-DIAG] Incremental extraction OK", .{});

            // Update extract dir name to reflect incremental slot
            const inc_extract_dir = std.fmt.allocPrint(
                self.allocator,
                "{s}/extracted-{d}",
                .{ snap_dir, active.slot },
            ) catch return full_extract_dir;

            if (std.fs.path.isAbsolute(full_extract_dir)) {
                std.fs.renameAbsolute(full_extract_dir, inc_extract_dir) catch return full_extract_dir;
            } else {
                std.fs.cwd().rename(full_extract_dir, inc_extract_dir) catch return full_extract_dir;
            }
            self.allocator.free(full_extract_dir);
            return inc_extract_dir;
        }

        return full_extract_dir;
    }

    /// Derive the local archive path from a SnapshotInfo
    fn snapshotArchivePath(self: *Self, sm: *vex_store.snapshot.SnapshotManager, info: *const vex_store.snapshot.SnapshotInfo, snap_dir: []const u8) ![]const u8 {
        _ = sm;
        // Derive filename from the download URL
        const url = info.download_url orelse return error.NoDownloadUrl;
        const url_filename = if (std.mem.lastIndexOf(u8, url, "/")) |idx| url[idx + 1 ..] else url;

        // If it has a parseable snapshot name, use it; otherwise use a generic name
        const filename = if (vex_store.snapshot.SnapshotInfo.fromFilename(url_filename) != null)
            url_filename
        else if (info.is_incremental)
            "incremental-snapshot.tar.zst"
        else
            "snapshot.tar.zst";

        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ snap_dir, filename });
    }

    fn updatePhase(self: *Self, phase: BootstrapPhase, _: f32) void {
        self.current_phase = phase;
    }

    fn formatPubkey(_: *Self, pk: core.Pubkey) [8]u8 {
        var buf: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}..{x:0>2}{x:0>2}", .{
            pk.data[0], pk.data[1], pk.data[30], pk.data[31],
        }) catch {};
        return buf;
    }
};

/// Walk the snapshot-captured staked vote-account set, fetch each account's
/// current state from AccountsDb, parse last_timestamp via vote_state_serde,
/// and seed the top_votes map. Lives in bootstrap.zig (not accounts.zig) so
/// that vex_store has no edge back into vex_svm/native/vote_state_serde.zig.
fn seedTopVotesFromSnapshot(db: *AccountsDb) void {
    const vote_serde = @import("native/vote_state_serde.zig");
    if (db.vote_account_stakes.len == 0) return;

    db.top_votes_lock.lock();
    defer db.top_votes_lock.unlock();

    var seeded: usize = 0;
    var skipped_no_data: usize = 0;
    var skipped_no_ts: usize = 0;
    for (db.vote_account_stakes) |entry| {
        const pk = core.Pubkey{ .data = entry.vote_pubkey };
        const acct = db._getRooted(&pk) orelse { skipped_no_data += 1; continue; };
        if (acct.data.len < 16) { skipped_no_data += 1; continue; }
        const vs = vote_serde.deserializeVoteState(acct.data) orelse {
            skipped_no_data += 1;
            continue;
        };
        // d16 v3 (2026-05-10): always-seed current state, including timestamp=0.
        // The runtime filter in computeStakeWeightedClockEstimate drops zero-
        // timestamp samples, so semantically equivalent — but ensures we
        // don't have a write-only entries-can-only-be-added invariant that
        // hides Agave-divergent vote-state.
        if (vs.last_timestamp.timestamp == 0) skipped_no_ts += 1;
        // Seed = the snapshot's rooted baseline (write_slot = rooted_slot);
        // always in-lineage via selectForFork's `<= rooted_slot` rule.
        if (db.top_votes.getOrPut(entry.vote_pubkey)) |gop| {
            if (!gop.found_existing) gop.value_ptr.* = .{};
            gop.value_ptr.upsert(.{
                .write_slot = db.rooted_slot,
                .last_vote_slot = vs.last_timestamp.slot,
                .last_vote_timestamp = vs.last_timestamp.timestamp,
                // Seed the fork-choice feed with each snapshot voter's tower top
                // so voting can build stake weight from slot 0 of this boot (not
                // only after each voter is re-observed). See TopVoteVersion doc.
                .tower_last_voted_slot = vs.lastVotedSlot() orelse 0,
            }, db.rooted_slot);
        } else |_| continue;
        seeded += 1;
    }
    std.log.debug("[BOOTSTRAP] top_votes seeded from snapshot: {d} entries ({d} no_data, {d} no_ts)\n", .{
        seeded, skipped_no_data, skipped_no_ts,
    });
}

/// Download progress callback — prints MB downloaded and speed
fn printDownloadProgress(progress: vex_store.snapshot.DownloadProgress) void {
    const mb_done = @as(f64, @floatFromInt(progress.downloaded_bytes)) / (1024.0 * 1024.0);
    const mb_total = @as(f64, @floatFromInt(progress.total_bytes)) / (1024.0 * 1024.0);
    const speed_mbps = progress.bytesPerSecond() / (1024.0 * 1024.0);
    if (mb_total > 0) {
        std.log.debug("\r[BOOTSTRAP] Download: {d:.1}/{d:.1} MB ({d:.1} MB/s, {d:.0}%)", .{
            mb_done, mb_total, speed_mbps, progress.percentComplete(),
        });
    } else {
        std.log.debug("\r[BOOTSTRAP] Download: {d:.1} MB ({d:.1} MB/s)", .{ mb_done, speed_mbps });
    }
}

/// Fetch EpochSchedule from a running RPC node via getEpochSchedule.
/// Used in genesis mode to pick up test-validator's 32-slot epoch config.
fn fetchEpochSchedule(allocator: Allocator, rpc_url: []const u8) !bank_mod.EpochSchedule {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const body =
        \\{"jsonrpc":"2.0","id":1,"method":"getEpochSchedule"}
    ;

    // Capture response body via Allocating writer
    var response_list = std.ArrayListUnmanaged(u8){};
    defer response_list.deinit(allocator);
    var response_writer = std.Io.Writer.Allocating.fromArrayList(allocator, &response_list);

    _ = try client.fetch(.{
        .location = .{ .url = rpc_url },
        .method = .POST,
        .payload = body,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .response_writer = &response_writer.writer,
    });

    // Recover list from Allocating writer
    response_list = response_writer.toArrayList();

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_list.items, .{});
    defer parsed.deinit();

    const rpc_result = parsed.value.object.get("result") orelse return error.InvalidRpcResponse;
    const spe = rpc_result.object.get("slotsPerEpoch") orelse return error.InvalidRpcResponse;
    const warmup_val = rpc_result.object.get("warmup") orelse return error.InvalidRpcResponse;
    const fne = rpc_result.object.get("firstNormalEpoch") orelse return error.InvalidRpcResponse;
    const fns_val = rpc_result.object.get("firstNormalSlot") orelse return error.InvalidRpcResponse;
    const lsso = rpc_result.object.get("leaderScheduleSlotOffset") orelse return error.InvalidRpcResponse;

    return bank_mod.EpochSchedule{
        .slots_per_epoch = @intCast(spe.integer),
        .leader_schedule_slot_offset = @intCast(lsso.integer),
        .warmup = warmup_val.bool,
        .first_normal_epoch = @intCast(fne.integer),
        .first_normal_slot = @intCast(fns_val.integer),
    };
}

/// Load an Ed25519 keypair from a JSON file (Solana CLI format: [u8; 64])
pub fn loadKeypairFromFile(_: Allocator, path: []const u8) !core.Keypair {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf: [1024]u8 = undefined;
    const len = try file.readAll(&buf);
    const content = buf[0..len];

    // Parse JSON array of u8 values: [1,2,3,...,64]
    var bytes: [64]u8 = undefined;
    var idx: usize = 0;

    var i: usize = 0;
    while (i < content.len and idx < 64) : (i += 1) {
        if (content[i] >= '0' and content[i] <= '9') {
            var num: u16 = 0;
            while (i < content.len and content[i] >= '0' and content[i] <= '9') : (i += 1) {
                num = num * 10 + @as(u16, content[i] - '0');
            }
            bytes[idx] = @intCast(num);
            idx += 1;
        }
    }

    if (idx != 64) return error.InvalidKeypairFile;

    return core.Keypair{
        .secret = bytes[0..64].*,
        .public = core.Pubkey{ .data = bytes[32..64].* },
    };
}
