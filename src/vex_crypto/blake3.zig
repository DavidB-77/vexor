//! Vexor BLAKE3 wrapper — pure-Zig stdlib BLAKE3.
//! @prov:crypto.blake3
//!
//! ITEM K (2026-05-04): The load-bearing accountLtHash BLAKE3 hot path in
//! src/vex_svm/bank.zig is routed through this wrapper, which is std.crypto's
//! pure-Zig BLAKE3. (The former Firedancer Ballet AVX-512 FFI backend was
//! removed 2026-07-12 — Vexor now runs a fully FFI-free crypto leaf.)

const std = @import("std");

pub const Backend = enum { stdlib };

pub const active_backend: Backend = .stdlib;

// Pure-Zig stdlib BLAKE3. Exposes .init(.{}) → .update(data) → .final(out).
pub const Blake3 = std.crypto.hash.Blake3;

// ── Boot-time self-test hook ──────────────────────────────────────────────────
// Historically cross-validated stdlib vs the Ballet FFI backend at boot. With
// the FFI backend removed there is a single (stdlib) implementation, so this is
// a no-op retained as a stable boot-sequence entry point (called from main.zig).
pub fn runBalletSelfTest() void {}
