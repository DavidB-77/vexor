const std = @import("std");
const vex_crypto = @import("vex_crypto");

pub const Pubkey = vex_crypto.Pubkey;
pub const Hash = vex_crypto.Hash;

/// Mirrors the lock-down state of a single Solana execution account at runtime.
pub const AccountMeta = struct {
    pubkey: Pubkey,
    lamports: u64,
    owner: Pubkey,
    
    /// Identifies the account as purely executable (a program code account)
    executable: bool,
    
    /// The current rent epoch this account owes or is paid up for.
    rent_epoch: u64,
    
    /// The dynamically allocated byte array for the account's actual data state.
    data: []u8,

    pub fn isExecutable(self: AccountMeta) bool {
        return self.executable;
    }
    
    pub fn isSystem(self: AccountMeta) bool {
        // System program id = all-zero (11111111... base58). Bind to a const lvalue so the
        // *const Pubkey eql() param has an addressable argument (Zig won't auto-ref an rvalue).
        const system_id = Pubkey.default();
        return self.owner.eql(&system_id);
    }
};

/// A single execution instruction bounded to a program id.
pub const Instruction = struct {
    program_id: Pubkey,
    /// Indices referencing the transaction's master keys array
    accounts: []const u8, 
    data: []const u8,
};

/// Mathematical layout of the Rent parameters used to charge for storage.
pub const Rent = struct {
    lamports_per_byte_year: u64,
    exemption_threshold: f64,
    burn_percent: u8,
};
