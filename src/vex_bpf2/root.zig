//! vex_bpf2 — Vexor BPF stack v2 umbrella.
//!
//! Spec-for-spec rebuild against agave-v4.0.0-beta.7 (testnet pin), with
//! solana-sbpf-v0.14.4 as the canonical VM-core reference and sig as the
//! Zig-idiom reference. See vault/rebuild-scope/ for the full plan and
//! the 14-section spec-completeness checklist.
//!
//! ## Module map (Wave 1+2 — landed)
//!
//!   M1  elf          — ELF parser + verifier-side header validation
//!   M2  memory       — Region + AlignedMemoryMap + gapped stack
//!   M3  verifier     — standalone bytecode verifier pass
//!   M4  interpreter  — per-opcode interpreter (V0/V1/V2/V3)
//!   M5  serialize    — input region byte-layout (18/18 fixture parity)
//!   M8  invoke_ctx   — InvokeContext + TransactionContext + InstrStack
//!   M8  sysvar_cache — populated cache for all 8 sysvars (vex-058 locked)
//!   M8  loader       — Upgradeable loader native instruction handlers
//!
//! ## Module map (Wave 3 — pending)
//!
//!   M6  syscalls     — full agave syscall registry (47 syscalls)
//!   M7  cpi          — CPI handler with translate/push/recurse/writeback/pop
//!   M9  builtins     — native builtin programs (System, Vote, Stake, …)
//!
//! ## Module map (Wave 3.5 + Wave 4 — pending)
//!
//!   trace            — module-boundary execution tracing + selfTest
//!   (top-level wire)  — replay_stage dispatch + --bpf-stack=v2 flag
//!
//! Public API surface is the union of each module's public API; consumers
//! may either import this umbrella and reach `vex_bpf2.<module>.<symbol>` or
//! import individual files directly. Both forms are supported.
//!
//! NOTE: `fixture.zig` / `fixture_runner.zig` are test harness scaffolding,
//! not part of the production API. They depend on `vex_store` and are only
//! loaded by their dedicated test step (`test-bpf-fixture`). They are NOT
//! re-exported here so that production callers importing `vex_bpf2` do not
//! drag the test-only `vex_store` graph into their module set.

// ── Wave 1: VM core building blocks ─────────────────────────────────────────

pub const elf = @import("elf.zig");
pub const memory = @import("memory.zig");
pub const serialize = @import("serialize.zig");

// ── Wave 2: Verifier + Interpreter ──────────────────────────────────────────

pub const verifier = @import("verifier.zig");
pub const interpreter = @import("interpreter.zig");

// ── Wave 1: Runtime adjacency (M8) ──────────────────────────────────────────

pub const invoke_ctx = @import("invoke_ctx.zig");
pub const sysvar_cache = @import("sysvar_cache.zig");

// ── Wave 3: M6 — Syscall registry ───────────────────────────────────────────
pub const syscalls = @import("syscalls.zig");

// ── Wave 3: M7 — Cross-Program Invocation handler ───────────────────────────
pub const cpi = @import("cpi.zig");

// ── Wave 3: M9 — Native builtin programs ────────────────────────────────────
pub const builtins = @import("builtins/mod.zig");

// ── Wave 3.5: trace layer + boot-time self-test dashboard ──────────────────
pub const trace = @import("trace.zig");
pub const self_test = @import("self_test.zig");

// ── Wave 4: runtime dispatch mode flag ──────────────────────────────────────
pub const dispatch_mode = @import("dispatch_mode.zig");

// ── Phase-1: Core-BPF Stake dual-path env gate (VEX_STAKE_BPF, default OFF) ──
pub const stake_bpf_flag = @import("stake_bpf_flag.zig");

// ── Wave 6A: V2 BPF program cache (shared by BPF dispatcher) ────────────────
pub const v2_program_cache = @import("v2_program_cache.zig");

// ── Stage-D: shadow-mode safety primitives (metrics + rate-limit + cache-tx) ─
pub const shadow_safety = @import("shadow_safety.zig");

// ── Stage-D follow-up: panic-safety harness for shadow execution ────────────
pub const shadow_panic_safety = @import("shadow_panic_safety.zig");

// Tests are loaded by their own dedicated build steps so that each step can
// declare exactly the module deps it needs (e.g. `test-bpf-fixture` brings in
// `core` + `vex_store` + `vex_crypto`, while `test-vex-bpf2-runtime` is a
// pure self-contained module). Do not add a blanket `test { _ = ... }` block
// here — that would cause every importer of root.zig to transitively pull in
// every test file's deps, forcing umbrella consumers to stub deps they don't
// actually use.
