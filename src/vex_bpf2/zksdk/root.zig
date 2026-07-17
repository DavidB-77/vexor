//! Import-resolution root for the ZK ElGamal proof port (task #11, 2026-06-19).
//!
//! Ported Sig modules reference `sig.crypto.ed25519`, `sig.zksdk.*`, and
//! `sig.runtime.program.zk_elgamal.*`, where `sig = @import("../lib.zig")` (Sig's shared root).
//! In the vex tree each ported module's `@import("../lib.zig")` / `@import("../../lib.zig")` is
//! repointed to THIS file (relative path adjusted per directory depth), which re-exposes the
//! same three namespaces over the local ports. This keeps every Sig module byte-identical apart
//! from its single root-import line. See ZK-ELGAMAL-PORT-PLAN-2026-06-19.md.

pub const crypto = struct {
    pub const ed25519 = @import("ed25519.zig");
};

pub const zksdk = @import("zksdk.zig");

pub const runtime = struct {
    pub const program = struct {
        pub const zk_elgamal = @import("zk_elgamal_types.zig");
    };
};
