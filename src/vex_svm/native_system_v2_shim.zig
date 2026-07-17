//! Module-root shim exposing native/system_v2.zig (+ its types) to the
//! vex_bpf2 differential KAT (kat_system_cpi_native_diff.zig). Rooted at
//! src/vex_svm/ so system_v2.zig's `@import("../types.zig")` /
//! `@import("nonce.zig")` resolve inside this module's boundary — the same
//! idiom as kat_create_with_seed_414674115.zig. Only needs vex_crypto.

pub const system_v2 = @import("native/system_v2.zig");
pub const types = @import("types.zig");
pub const Pubkey = types.Pubkey;
pub const AccountMeta = types.AccountMeta;
pub const InstrCtx = system_v2.InstrCtx;
pub const execute = system_v2.execute;
