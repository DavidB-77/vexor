//! Thin module shim so a KAT can root the System processor + its `../types.zig` dependency under ONE
//! module path. native/system.zig imports `../types.zig`; if native/system.zig is itself a module
//! ROOT, that `../` escapes the module boundary (Zig: "import of file outside module path"). Rooting
//! THIS file (one directory up, at src/vex_svm/) makes native/system.zig's `../types.zig` resolve to
//! src/vex_svm/types.zig — inside the boundary. Re-exports the symbols the tx-bearing exec KAT needs.
//! Pure aliases; no behavior. Run via the test-txbearing-exec target.

const system = @import("native/system.zig");

pub const AccountMeta = system.AccountMeta;
pub const Pubkey = system.Pubkey;
pub const PROGRAM_ID = system.PROGRAM_ID;
pub const InstructionOpcodes = system.InstructionOpcodes;
pub const executeTransfer = system.executeTransfer;
pub const executeCreateAccount = system.executeCreateAccount;
