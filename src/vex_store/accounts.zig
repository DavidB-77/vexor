//! Vexor Accounts Database — public aggregator (rebuild module 25 SPLIT).
//! accounts.zig is intentionally a thin re-export of appendvec.zig /
//! account_storage.zig / accounts_db.zig so every downstream `@import("accounts.zig").<Sym>`
//! (parallel_snapshot, unrooted_ring, snapshot, main, fork_choice_feed, ...) stays
//! byte-compatible with the pre-split monolith.
const appendvec = @import("appendvec.zig");
const account_storage = @import("account_storage.zig");
const accounts_db = @import("accounts_db.zig");

// Core DB + index / cache / buffers / vote (accounts_db.zig)
pub const AccountsDb = accounts_db.AccountsDb;
pub const AccountIndex = accounts_db.AccountIndex;
pub const AccountCache = accounts_db.AccountCache;
pub const BulkLoadBuffer = accounts_db.BulkLoadBuffer;
pub const TopVote = accounts_db.TopVote;
pub const TopVoteVersion = accounts_db.TopVoteVersion;
pub const ClockEpochAnchor = accounts_db.ClockEpochAnchor;

// Leaf storage types (appendvec.zig)
pub const Account = appendvec.Account;
pub const AccountView = appendvec.AccountView;
pub const AccountLocation = appendvec.AccountLocation;
pub const SlotOverlay = appendvec.SlotOverlay;
pub const AppendVec = appendvec.AppendVec;

// Store-management layer (account_storage.zig)
pub const AccountStorage = account_storage.AccountStorage;

// Forensic AppendVec counters referenced externally as `accounts.g_av_*`
// (vex_svm/replay_stage.zig:9040-9046 / :4381 heap-report). Re-exported as
// pointer-aliases: a container-level `const` cannot bind a mutable `var`, but
// `.load()/.fetchAdd()` auto-deref through the pointer, so the call sites are
// unchanged from the origin-tree monolith's direct `pub var` access.
//
// REBUILD module 73 (2026-07-07): the §3.7 exe force-compiles the replay_stage
// heap-report method body (via main.zig → replayWorker/onSlotCompleted), which
// references ALL SEVEN counters. m25's SPLIT forwarded only g_av_heap_count (the
// only one any then-in-tree consumer used — replay_stage was not migrated yet);
// its "other counters have no external referent" note was correct AT m25 but is
// now superseded. The 7 live in their owning split files: 5 in appendvec.zig,
// 2 (reclaimed_*) in account_storage.zig.
pub const g_av_heap_count = &appendvec.g_av_heap_count;
pub const g_av_heap_cap_bytes = &appendvec.g_av_heap_cap_bytes;
pub const g_av_appended_bytes = &appendvec.g_av_appended_bytes;
pub const g_av_mmap_count = &appendvec.g_av_mmap_count;
pub const g_av_mmap_bytes = &appendvec.g_av_mmap_bytes;
pub const g_av_reclaimed_count = &account_storage.g_av_reclaimed_count;
pub const g_av_reclaimed_bytes = &account_storage.g_av_reclaimed_bytes;
