//! Vexor BPF Runtime
//!
//! Native Zig SBPF v0 virtual machine — no external C dependencies.
//! Inspired by Firedancer fd_vm and Agave solana-rbpf; rewritten as
//! first-class Vexor components.
//!
//! Architecture:
//!
//!   ┌────────────────────────────────────────────┐
//!   │                 SbpfExecutor               │  bank.executeBpfProgram
//!   │  serialise accounts → run VM → deserialise │
//!   └──────────────────┬─────────────────────────┘
//!                      │
//!          ┌───────────┴────────────┐
//!          │        BpfVm           │  interpreter.zig
//!          │  fetch / decode / step │
//!          └───────────┬────────────┘
//!                      │  translate(vm_addr)
//!          ┌───────────┴────────────┐
//!          │      VmContext         │
//!          │  4 memory regions:     │
//!          │   0x100000000 program  │  ← rodata_combined (read-only)
//!          │   0x200000000 stack    │  ← stack_buf
//!          │   0x300000000 heap     │  ← heap_buf
//!          │   0x400000000 input    │  ← serialised accounts (r2)
//!          └────────────────────────┘
//!
//!   Syscalls (syscalls.zig) — murmur3_32 dispatch, all IDs verified:
//!     abort, sol_panic_, sol_log_, sol_log_64_, sol_log_pubkey,
//!     sol_memcpy_, sol_memmove_, sol_memcmp_, sol_memset_,
//!     sol_sha256, sol_keccak256, sol_blake3,
//!     sol_create_program_address_, sol_try_find_program_address,
//!     sol_get_clock_sysvar, sol_get_rent_sysvar, sol_alloc_free_
//!
//!   CPI (sol_invoke_signed_c / _rust): returns VmError.CpiRequired.
//!   Executor catches this and falls back to the RPC shadow BPF path.

const std = @import("std");

pub const elf_loader    = @import("elf_loader.zig");
pub const interpreter   = @import("interpreter.zig");
pub const syscalls      = @import("syscalls.zig");
pub const sbpf_executor = @import("sbpf_executor.zig");

// New sBPF VM modules (V0–V3 full implementation)
pub const vm_sbpf        = @import("vm_sbpf.zig");
pub const vm_memory      = @import("vm_memory.zig");
pub const vm_executable  = @import("vm_executable.zig");
pub const vm_interpreter = @import("vm_interpreter.zig");
pub const vm_syscalls    = @import("vm_syscalls.zig");

pub const ElfLoader      = elf_loader.ElfLoader;
pub const LoadedProgram  = elf_loader.LoadedProgram;
pub const BpfVm          = interpreter.BpfVm;
pub const VmContext      = interpreter.VmContext;
pub const VmError        = interpreter.VmError;
pub const SbpfExecutor   = sbpf_executor.SbpfExecutor;
pub const AccountEntry   = sbpf_executor.AccountEntry;
pub const AccountMutation = sbpf_executor.AccountMutation;
// FIX-1a (2026-06-10, task #65): top-level run classification (genuine
// program error vs Vexor plumbing) read by replay_stage.executeBpfProgramCore.
pub const TopLevelRunOutcome = sbpf_executor.TopLevelRunOutcome;

/// Compute budget constants — used by bank.zig when processing transactions.
/// Kept here so bank.zig can reference bpf.ComputeBudget.DEFAULT_UNITS
/// without depending on a specific executor implementation.
pub const ComputeBudget = struct {
    pub const DEFAULT_UNITS: u64 = 200_000;
    pub const MAX_UNITS:     u64 = 1_400_000;
    pub const CPI_BASE_COST: u64 = 1_000;
    pub const SHA256_BASE_COST:    u64 = 85;
    pub const SHA256_BYTE_COST:    u64 = 1;
    pub const KECCAK256_BASE_COST: u64 = 36;
    pub const KECCAK256_BYTE_COST: u64 = 1;
    pub const SECP256K1_COST:      u64 = 25_000;
};
