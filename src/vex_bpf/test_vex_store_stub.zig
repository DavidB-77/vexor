//! Minimal vex_store stub for bpf_fixture_test.
//!
//! sbpf_executor.zig references `storage.AccountsDb` as `?*AccountsDb`.
//! When the fixture runner only calls `SbpfExecutor.execute()`, this pointer
//! is null and the stub is never dereferenced. The stub exists only to make
//! the type lookup compile.

const std = @import("std");
const core = @import("core");

pub const AccountView = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: core.Epoch,
    data: []const u8,
};

pub const AccountsDb = struct {
    pub fn getAccount(self: *@This(), pubkey: *const core.Pubkey) ?AccountView {
        _ = self;
        _ = pubkey;
        return null;
    }
};

// Some callers reference storage.accounts.AccountsDb instead of storage.AccountsDb.
pub const accounts = struct {
    pub const AccountsDb = struct {
        pub fn getAccount(self: *@This(), pubkey: *const core.Pubkey) ?AccountView {
            _ = self;
            _ = pubkey;
            return null;
        }
    };
};
