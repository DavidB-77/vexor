//! Vexor BPF2 — Bank ↔ vex_bpf2.SysvarCache adapter (Wave 6A).
//!
//! `vex_bpf2.sysvar_cache.SysvarCache.populateFromBank(bank)` is duck-typed
//! via `@hasDecl` over the 8 `getXxxBytes(*const Bank) ?[]const u8` methods.
//! Vexor's `vex_svm/bank.zig` does not expose those getters directly — sysvar
//! state lives in the AccountsDb at well-known pubkeys. This adapter wraps
//! `(*Bank, *AccountsDb)` and exposes the duck-typed surface SysvarCache
//! expects, reading bytes from AccountsDb on demand.
//!
//! ── Lifetime contract ─────────────────────────────────────────────────────
//! The slices returned by each getter point INTO the AccountsDb's mmap-backed
//! storage. `populateFromBank` immediately `dupe`s them into the cache, so
//! the adapter and the underlying account need only outlive the populate
//! call. Do NOT hold returned slices past `populateFromBank` return.
//!
//! ── vex-058 invariant ────────────────────────────────────────────────────
//! If a sysvar account is missing from the AccountsDb, the getter returns
//! `null` (NOT a zeroed buffer). SysvarCache then records "not populated"
//! and any read fires `error.SysvarNotPopulated`. Same shape as Agave.

const std = @import("std");

const sysvar_cache_mod = @import("vex_bpf2").sysvar_cache;
const accounts_mod = @import("vex_store").accounts;
const core = @import("core");
const Bank = @import("bank.zig").Bank;
const AccountsDb = accounts_mod.AccountsDb;

/// Adapter; exposes the 8 `getXxxBytes` methods SysvarCache.populateFromBank
/// duck-checks via `@hasDecl`.
///
/// Construct on the stack just before populate, do not retain past the call.
pub const BankSysvarAdapter = struct {
    bank: *const Bank,
    db: *AccountsDb,

    pub fn init(bank: *const Bank, db: *AccountsDb) BankSysvarAdapter {
        return .{ .bank = bank, .db = db };
    }

    fn lookupBytes(self: *const BankSysvarAdapter, pubkey: [32]u8) ?[]const u8 {
        // r75-bug-class-d9 (2026-05-06): walk bank.pending_writes overlay
        // BEFORE db.getAccount fallback. Per-slot sysvar updates
        // (updateClockSysvar / updateSlotHashesSysvar / ...) write to
        // bank.pending_writes — they're flushed to db at end of slot, not
        // inline. Pre-fix, V2 BPF dispatch's SysvarCache.populateFromBank
        // read the PRE-slot sysvar bytes (whatever was last persisted to
        // db at end of previous slot or snapshot bootstrap), so BPF
        // programs that called Clock::get / SlotHashes::get / etc. saw
        // stale data. The reference node's MessageProcessor reads fresh per-slot
        // sysvars. This was a likely carrier of any post-slot-N divergence
        // where a BPF program reads sysvars and writes derived state.
        // Same pattern as the V2 dispatch account-snapshot overlay at
        // replay_stage.zig:3771-3789 and the System overlay at fa51331.
        var pwi: usize = self.bank.pending_writes.items.len;
        while (pwi > 0) {
            pwi -= 1;
            const pw = &self.bank.pending_writes.items[pwi];
            if (std.mem.eql(u8, &pw.pubkey.data, &pubkey)) {
                if (pw.data.len == 0) return null;
                return pw.data;
            }
        }
        const pk = core.Pubkey{ .data = pubkey };
        const acct = self.db.getAccountInSlot(&pk, self.bank.slot, self.bank.ancestors()) orelse return null;
        // Sysvar accounts are non-empty by construction; if the account
        // exists but data is empty, treat as not-populated (vex-058).
        if (acct.data.len == 0) return null;
        return acct.data;
    }

    pub fn getClockBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_CLOCK_ID);
    }
    pub fn getRentBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_RENT_ID);
    }
    pub fn getEpochScheduleBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_EPOCH_SCHEDULE_ID);
    }
    pub fn getSlotHashesBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_SLOT_HASHES_ID);
    }
    pub fn getSlotHistoryBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_SLOT_HISTORY_ID);
    }
    pub fn getStakeHistoryBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_STAKE_HISTORY_ID);
    }
    pub fn getEpochRewardsBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_EPOCH_REWARDS_ID);
    }
    pub fn getLastRestartSlotBytes(self: *const BankSysvarAdapter) ?[]const u8 {
        return self.lookupBytes(sysvar_cache_mod.SYSVAR_LAST_RESTART_SLOT_ID);
    }
};
