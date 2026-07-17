//! Vexor BPF2 — Wave 6A V2 program cache.
//!
//! In-memory keyed cache of fully-loaded `vex_bpf2.elf.Executable`s, indexed
//! by program pubkey. Avoids re-parsing + re-verifying the same ELF on every
//! transaction in the same slot.
//!
//! ── Lifecycle contract (CRITICAL — read before changing) ──────────────────
//!
//! The cache OWNS every `*Executable` it stores. Callers BORROW.
//!
//!   • On cache MISS:
//!       1. caller parses the ELF (heap-allocates `*Executable`),
//!       2. calls `cache.put(pid, exe_ptr, slot, programdata_slot)`,
//!       3. cache takes ownership; caller must NOT free the executable.
//!   • On cache HIT:
//!       caller borrows `entry.executable` for the dispatch; must NOT free
//!       it on dispatch exit.
//!   • Eviction (manual or `invalidateBeforeSlot`):
//!       cache calls `executable.deinit()` then `allocator.destroy(exe)`.
//!
//! Single-threaded by design: every replay thread owns its own cache (or
//! synchronises externally). Wave 6A wires one cache per replay thread; a
//! shared cache with a lock can be added when block-production lands.
//!
//! ── Invalidation strategy ─────────────────────────────────────────────────
//!
//! Two axes:
//!   1. Program upgrade — programdata account written, `last_modified_slot`
//!      advances. Caller compares the cache entry's `program_data_slot` to
//!      the bank's current view; on mismatch → `invalidate(pid)` + reload.
//!   2. Slot rollover — entries older than `min_keep_slot` are dropped via
//!      `invalidateBeforeSlot(min_keep_slot)`. Production code calls this
//!      from `Bank.freeze()` after pruning rooted forks.
//!
//! Cache misses are NOT a correctness issue — they only cost re-parse time.
//! Cache hits are NOT a correctness issue either — the executable is
//! immutable post-load, so concurrent borrows are safe.
//!
//! ── Multi-thread migration prep (Wave 6 latent #5) ────────────────────────
//!
//! TODAY (single-writer model):
//!   • The cache is process-scoped (one `g_v2_program_cache` global in
//!     `replay_stage.zig`) and accessed exclusively from the replay thread.
//!     Single-threaded replay makes lock-free correct: every `put` /
//!     `invalidate*` happens between transactions, never concurrently with
//!     a borrow.
//!   • Returned `*V2ProgramCacheEntry` and `*Executable` pointers are STABLE
//!     for the duration of the dispatch frame — but `std.AutoHashMapUnmanaged`
//!     re-hashes on insert, which CAN move the entry value memory. The
//!     resolver path holds the `*Executable` itself (not the entry struct),
//!     and `*Executable` is heap-allocated separately, so the dereference is
//!     safe even if `put` re-hashes the map. Do NOT cache `*V2ProgramCacheEntry`
//!     across a `put`.
//!
//! TOMORROW (block-production):
//!   • Block-production runs VerifyTile + Replay concurrently. The cache must
//!     move from a process-scoped global into a `ReplayStage`-instance field
//!     (or a shared `Arc<Mutex<...>>`-equivalent).
//!   • Concurrency primitive: `std.Thread.RwLock`. Reads (the resolver path)
//!     are by far the hot case; writes (`put`/`invalidate`) only fire on
//!     program upgrades or slot rollover. RwLock matches that asymmetry.
//!   • Pointer stability: entry-value pointers must remain valid across
//!     concurrent reads even when one writer is doing `put`. The current
//!     `std.AutoHashMapUnmanaged` design re-hashes on grow, invalidating
//!     entry pointers. The migration MUST replace the value storage with
//!     either a slab/arena allocator that returns stable pointers, OR a
//!     copy-on-write model where readers atomically swap to a new immutable
//!     snapshot.
//!   • Until then, callers MUST copy any per-entry data they need before
//!     releasing the read lock. The `ProgramResolver.resolve` adapter below
//!     returns `*const Executable`; that pointer is heap-stable (not stored
//!     inside the hashmap), so it survives a concurrent `put`. This is the
//!     ONLY field on `V2ProgramCacheEntry` that's safe to keep across
//!     unlocked sections.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-079 — does NOT live in this file; the cache is content-blind.
//!   • vex-058 — sysvar invariant; this file does not touch sysvars.

const std = @import("std");

const elf = @import("elf.zig");
const cpi = @import("cpi.zig");
const sysvar_cache = @import("sysvar_cache.zig");

pub const Executable = elf.Executable;

/// One cached program entry.
///
/// `executable` is heap-allocated and owned by the cache. `cached_at_slot`
/// records the bank slot at which the entry was inserted (for slot-based
/// pruning). `program_data_slot` records the programdata account's
/// `last_modified_slot` AT INSERT TIME — callers compare against the bank's
/// current view to detect upgrades.
pub const V2ProgramCacheEntry = struct {
    executable: *Executable,
    cached_at_slot: u64,
    program_data_slot: u64,
};

/// Pubkey-keyed cache of loaded BPF programs.
pub const V2ProgramCache = struct {
    map: std.AutoHashMapUnmanaged([32]u8, V2ProgramCacheEntry),
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) V2ProgramCache {
        return .{
            .map = .{},
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *V2ProgramCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |entry| {
            entry.executable.deinit();
            self.allocator.destroy(entry.executable);
        }
        self.map.deinit(self.allocator);
        self.map = .{};
    }

    /// Borrow lookup. Returned pointer is valid until the next mutating
    /// call (`put` / `invalidate*`). Caller MUST NOT free the executable.
    pub fn get(self: *V2ProgramCache, program_id: [32]u8) ?*V2ProgramCacheEntry {
        return self.map.getPtr(program_id);
    }

    /// Insert. Cache takes ownership of `executable`. If a prior entry exists
    /// for `program_id`, it is freed (deinit + destroy) and replaced.
    pub fn put(
        self: *V2ProgramCache,
        program_id: [32]u8,
        executable: *Executable,
        cached_at_slot: u64,
        program_data_slot: u64,
    ) !void {
        if (self.map.fetchRemove(program_id)) |kv| {
            kv.value.executable.deinit();
            self.allocator.destroy(kv.value.executable);
        }
        try self.map.put(self.allocator, program_id, .{
            .executable = executable,
            .cached_at_slot = cached_at_slot,
            .program_data_slot = program_data_slot,
        });
    }

    /// Drop the entry for `program_id` (freeing its executable). No-op if
    /// not present.
    pub fn invalidate(self: *V2ProgramCache, program_id: [32]u8) void {
        if (self.map.fetchRemove(program_id)) |kv| {
            kv.value.executable.deinit();
            self.allocator.destroy(kv.value.executable);
        }
    }

    /// Drop every entry whose `cached_at_slot < min_keep_slot`. Used at
    /// slot rollover to bound memory.
    pub fn invalidateBeforeSlot(self: *V2ProgramCache, min_keep_slot: u64) void {
        var to_remove: std.ArrayListUnmanaged([32]u8) = .{};
        defer to_remove.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.cached_at_slot < min_keep_slot) {
                to_remove.append(self.allocator, kv.key_ptr.*) catch break;
            }
        }
        for (to_remove.items) |pid| self.invalidate(pid);
    }

    pub fn count(self: *const V2ProgramCache) usize {
        return self.map.count();
    }

    // ──────────────────────────────────────────────────────────────────────
    // ProgramResolver adapter — Wave 6C-1
    // ──────────────────────────────────────────────────────────────────────
    //
    // The cache implements the `cpi.ProgramResolver` shape so M7's
    // `handleSolInvokeSigned` can recurse into BPF callees. The resolver
    // ONLY surfaces a verified-and-loaded `*Executable`; it does NOT take
    // any responsibility for upgrade detection (programdata_slot mismatch
    // is a dispatcher-side concern — the cache is content-blind by design,
    // see header comment). When the dispatcher detects an upgrade it calls
    // `cache.invalidate(pid)` and the next CPI lookup will miss → reload.
    //
    // Lifetime: the returned `*const Executable` lives until the next
    // cache-mutating call (`put` / `invalidate` / `invalidateBeforeSlot` /
    // `deinit`). M7 only borrows it for the duration of the recursive
    // `Vm.run`, which completes before any cache mutation.

    fn resolverThunk(ctx: *anyopaque, pid: sysvar_cache.Pubkey32) ?*const elf.Executable {
        const self: *V2ProgramCache = @ptrCast(@alignCast(ctx));
        const entry = self.get(pid) orelse return null;
        return entry.executable; // *Executable coerces to *const Executable
    }

    /// Resolver vtable singleton — module-private, address-stable.
    const RESOLVER_VTABLE: cpi.ProgramResolver.VTable = .{
        .resolve = resolverThunk,
    };

    /// Adapter: wrap this cache as a `cpi.ProgramResolver`. The returned
    /// value contains a back-pointer to `self`, so it is only valid while
    /// `self` outlives the resolver. Cheap to call (no allocation).
    pub fn asResolver(self: *V2ProgramCache) cpi.ProgramResolver {
        return .{
            .ctx = @ptrCast(self),
            .vtable = &RESOLVER_VTABLE,
        };
    }

    /// Get-or-miss helper that compares `expected_pd_slot` against the
    /// cached entry's `program_data_slot`. On mismatch, evicts and returns
    /// null so the caller reloads from the bank.
    ///
    /// Use this instead of bare `get()` whenever you have a fresh
    /// programdata `last_modified_slot` from AccountsDb — that's the
    /// dispatcher-side upgrade-detection path. `expected_pd_slot=0`
    /// disables the check (matches non-upgradeable loader v2 programs
    /// that have no programdata slot).
    pub fn getFresh(
        self: *V2ProgramCache,
        program_id: [32]u8,
        expected_pd_slot: u64,
    ) ?*V2ProgramCacheEntry {
        const entry = self.map.getPtr(program_id) orelse return null;
        if (expected_pd_slot != 0 and entry.program_data_slot != expected_pd_slot) {
            self.invalidate(program_id);
            return null;
        }
        return entry;
    }
};

// Tests live in the v2 BPF path test root so the cache doesn't pull in a
// dedicated test step.
