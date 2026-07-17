//! Vexor Storage Module (vex_store)
//!
//! Module-root re-exports for the account/ledger/snapshot storage stack.
//!
//! CLEAN pass (rebuild module 27, 2026-07-06): the original header carried a
//! "3-tier RAM/NVMe/Archive" architecture diagram describing `StorageManager`
//! (below), which is dead code (zero constructors anywhere in the codebase —
//! it was the only thing keeping `ledger.zig`/`blockstore.zig`/the `ramdisk`
//! family alive). That diagram + StorageManager + every re-export whose
//! source file is DEAD/DELETE per the file manifest have been dropped here;
//! the sole behavior-affecting change is comment/dead-branch hygiene — every
//! remaining re-export is unedited. See REBUILD-LEDGER.md module-27 row for
//! the full whole-repo caller-evidence trail per dropped symbol.

const std = @import("std");
const core = @import("core");

// PR-S1 (2026-05-15): Sig-pattern per-slot overlay (ports Sig's Unrooted.zig).
// Not yet wired into AccountsDb readers; PR-S2 will replace `unrooted_overlay`.
pub const sig_overlay = @import("sig_overlay.zig");
pub const SigOverlay = sig_overlay;

pub const accounts = @import("accounts.zig");
pub const recorder = @import("recorder.zig");

// SB-2 (2026-06-17): RPC block/transaction-history stores. Standalone (NOT hung off LedgerDb — which
// is never instantiated in the live binary). Created in main.zig under the -Drpc_store/VEX_RPC_STORE
// gate, populated on the replay path, read by the RPC handlers. Exporting them here (a) makes
// `storage.BlockStore`/`storage.TxStatusStore` resolve in rpc_methods.zig and replay_stage.zig and
// (b) pulls their previously-dead-on-disk KATs into the `refAllDecls` test below.
pub const block_store = @import("block_store.zig");
pub const BlockStore = block_store.BlockStore;
pub const StoredBlock = block_store.StoredBlock;
pub const StoredTx = block_store.StoredTx;
pub const StoredReward = block_store.StoredReward;
pub const tx_status_store = @import("tx_status_store.zig");
pub const TxStatusStore = tx_status_store.TxStatusStore;

// REBUILD module 72 (2026-07-07): RESTORE the `ledger`/`LedgerDb` re-export that
// module-27's CLEAN dropped as "DEAD" (StorageManager was its only caller then).
// It is now LIVE: the module-72 §J/§K network landing brought in tvu.zig
// (`storage.LedgerDb` field on TvuService's ctx) + rpc_methods.zig
// (`ledger_db: ?*storage.LedgerDb` on RpcContext), matching fix105 root.zig:47/94.
// ledger.zig re-disposed DELETE→KEEP verbatim-carry (403 LoC, imports only
// core+std — self-contained; md5 58397b93…). The pointer is null in the live
// binary (never instantiated), but its TYPE must resolve for the RPC/TVU closure.
pub const ledger = @import("ledger.zig");
pub const LedgerDb = ledger.LedgerDb;

// REBUILD module 73 (2026-07-07): RESTORE the `async_io` re-export that module-27's
// CLEAN dropped as "DEAD" (StorageManager was its only cited caller then, and the
// manifest classed async_io.zig DELETE on "delete WITH the bootstrap wiring + init
// param"). The §3.7 exe force-compile proves it LIVE: bootstrap.zig (whole-file KEEP,
// module 71 — main.zig:604 runValidator → ValidatorBootstrap.bootstrap) calls
// `vex_store.async_io.AsyncIoManager.init(...)` @149/@558. async_io.zig re-disposed
// DELETE→KEEP verbatim-carry (420 LoC, std-only, md5 42b7dce7…; runtime/hashes/
// block_producer/ledger re-dispose precedent). The AccountsDb init call-site strip
// (accounts_db.zig takes ?*anyopaque, ignores it) stays a post-migration refactor.
pub const async_io = @import("async_io.zig");

// snapshot.zig SPLIT (rebuild module 27): discovery/download/extract/load
// AND the SnapshotManager save/create paths could not be separated (one
// struct, used monolithically by every external caller — see the module-27
// ledger row) — the whole SnapshotManager stays in snapshot_boot.zig. Only
// the byte-format-critical AppendVec writer primitives (BufferedAvWriter/
// SyncingAvWriter + the fork-BGSAVE child helpers) were split out, into
// snapshot_writer.zig, which snapshot_boot.zig imports internally — nothing
// external ever touched those directly, so no new export is added here. The
// `snapshot` alias name is kept pointing at the new file so every existing
// `vex_store.snapshot.*` / `vex_store.SnapshotManager` dotted-access call
// site (e.g. src/vex_svm/bootstrap.zig, not yet migrated) stays unchanged.
pub const snapshot = @import("snapshot_boot.zig");
pub const snapshot_manifest = @import("snapshot_manifest.zig");

// Streaming decompression module 22 SPLIT: the caller-less pipeline was
// deleted; only `zstdSelfTest` (main.zig:249's boot KAT) + the byte-exact
// zstd decode path survive, in the tiny `zstd_selftest.zig`. The submodule
// alias name `streaming_decompress` is kept pointing at the new file so
// `vex_store.streaming_decompress.zstdSelfTest` (main.zig:249, not yet
// migrated) resolves unchanged when main.zig lands. The 3 individual type
// re-exports below it (StreamingDecompressor/CompressionType/
// DecompressProgress) are NOT restored — module 22 proved (repo-wide grep)
// they have zero external callers one level up from this root and flagged
// trimming them as this module's job.
pub const streaming_decompress = @import("zstd_selftest.zig");

pub const parallel_snapshot = @import("parallel_snapshot.zig");

// Re-exports
pub const AccountsDb = accounts.AccountsDb;
pub const SnapshotManager = snapshot.SnapshotManager;
pub const SnapshotInfo = snapshot.SnapshotInfo;
pub const SnapshotPair = snapshot.SnapshotPair;

// Parallel snapshot loading for fast catch-up
pub const ParallelSnapshotLoader = parallel_snapshot.ParallelSnapshotLoader;
pub const generateTestFixture = parallel_snapshot.generateTestFixture;

test {
    std.testing.refAllDecls(@This());
}
