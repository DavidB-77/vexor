//! Vexor BPF v2 — memory layer (M2)
//!
//! Spec-for-spec rebuild of the sBPF memory map. This is a clean-room mirror
//! of `solana-sbpf v0.14.4` `src/memory_region.rs` written in Zig 0.15.2,
//! with idiom guidance from `sig/src/vm/memory.zig`.
//!
//! Reference targets (single source of truth for semantics):
//!   solana-sbpf v0.14.4  solana-sbpf-v0.14.4/src/memory_region.rs
//!     - MemoryRegion          (lines 42-137)
//!     - vm_to_host            (lines 108-136)  ← gapped translation math
//!     - AlignedMemoryMapping  (lines 348-449)
//!     - MemoryMapping::map    (lines 513-526)
//!   sig                  sig/src/vm/memory.zig
//!     - Region.translate      (lines 270-289)  ← Zig idiom + null host_slice handling
//!     - AlignedMemoryMap      (lines 316-396)
//!     - VIRTUAL_ADDRESS_BITS  (line 18)
//!   agave v4.0.0-beta.7  SHA 65f2d111…
//!
//! Vexor invariants preserved (see `fix_ledger.md`):
//!   vex-152m  V0 stack region MUST use gapped layout — frame + gap = 2× advance.
//!             Region.gap_size > 0 indicates gapped; gap_size == 0 indicates flat.
//!   vex-152n2 translate() MUST guard `vm_addr < self.vm_addr` BEFORE subtraction
//!             to avoid u64 wrap that masquerades as a giant in-range offset.
//!   vex-079   BPF_ALIGN_OF_U128 = 8 (NOT 16). Per-account input serializer
//!             alignment in M5 (serialize.zig) must use 8-byte stride; this
//!             constant is exported here so all VM-side modules agree.
//!
//! SIMD inventory (gates that touch this file’s semantics):
//!   SIMD-0166 Dynamic stack frames                 ACTIVE on testnet+mainnet
//!             (gating handled in vm_sbpf.zig version flags; this file is
//!              version-agnostic — the executor passes per-call regions in.)
//!   Direct-mapping (V4)                            DORMANT (gates value:null on testnet)
//!     7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz   sBPF v4 enable
//!     CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE  account-data direct mapping
//!     Until both gates flip, `Config.direct_mapping = false` is hard-wired.
//!   SIMD-0096 Reward full priority fee             ACTIVE — fee burn handled
//!             in fee_distribution.rs, not memory; included here only as a
//!             reminder that vex-060 reverts vex-056’s burn miscalculation.
//!
//! Ordering of regions in the aligned mapping (matches agave VIRTUAL_ADDRESS_BITS=32):
//!     0x000000000  bytecode/program  (RO; SBPFv3+)
//!     0x100000000  rodata            (RO)
//!     0x200000000  stack             (RW; gapped on V0/V1)
//!     0x300000000  heap              (RW)
//!     0x400000000  input             (RW; trailing MAX_PERMITTED_DATA_INCREASE slack)
//!
//! Public surface (exact spec from M2 brief):
//!     AccessError, MemoryRegionAccess
//!     Region { fromSlice, fromConst, initGapped, translate }
//!     AlignedMemoryMap { init, deinit, vmap }

const std = @import("std");

// ── Constants ────────────────────────────────────────────────────────────────
//
// VIRTUAL_ADDRESS_BITS — agave sbpf/src/ebpf.rs   (mirrored sig:18)
//   Each region occupies the slot identified by the upper 32 bits of the vm_addr.
pub const VIRTUAL_ADDRESS_BITS: u6 = 32;
pub const MM_REGION_SIZE: u64 = @as(u64, 1) << VIRTUAL_ADDRESS_BITS;

// Region base addresses — agave sbpf/src/ebpf.rs MM_*_START
// ⚠️ FOOTGUN: BYTECODE/RODATA here are NAME-SWAPPED vs canonical. Canonical
// (anza-sbpf v0.21.0 ebpf.rs:43-45 = rc.1 pin; FD fd_vm_base.h:186-188) defines
// MM_RODATA_START=0 and MM_BYTECODE_START=0x100000000 — the OPPOSITE of below.
// Vexor's V0/V1/V2 region build (v2_dispatch.zig / cpi.zig) places text@0 +
// rodata@slot1 to satisfy the O(1) `vm_addr>>32==idx` map, and is bank-exact on
// every exercised path, so these (mislabelled) values are load-bearing for v0-v2
// and must NOT be globally swapped (would break the working voting path). For V3
// the region builders DELIBERATELY bypass these constants and source vaddrs from
// the elf accessors (rodataVaddr()=0, programRegionVaddr()=0x1<<32), which ARE
// canonical (elf.zig:216-218 defines the constants correctly). Treat the names
// below as historical; never reference MM_BYTECODE_START/MM_RODATA_START for v3.
pub const MM_BYTECODE_START: u64 = 0x000000000;
pub const MM_RODATA_START: u64 = 0x100000000;
pub const MM_STACK_START: u64 = 0x200000000;
pub const MM_HEAP_START: u64 = 0x300000000;
pub const MM_INPUT_START: u64 = 0x400000000;

// vex-079: BPF_ALIGN_OF_U128 — input serializer alignment stride.
// Agave/Firedancer/sig agree on 8 (NOT 16). This constant is referenced by
// the M5 serializer; it lives here so every VM-side module imports the same
// value and a single edit updates the whole subsystem.
pub const BPF_ALIGN_OF_U128: u64 = 8;

// MAX_PERMITTED_DATA_INCREASE — solana-program-entrypoint constant.
// The input region for a CPI’d account includes 10240 bytes of trailing slack
// for in-place realloc, and `vmap` MUST be able to address into that slack.
// Tests below exercise the boundary.
pub const MAX_PERMITTED_DATA_INCREASE: u64 = 10240;

// MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION — Agave
// `transaction-context/src/lib.rs:23` (`MAX_ACCOUNT_DATA_LEN(10 MiB) * 2`).
// This is the CUMULATIVE per-TRANSACTION account-data growth budget, a distinct
// cap from the per-INSTRUCTION `MAX_PERMITTED_DATA_INCREASE` above. The two must
// not be conflated: a single realloc is capped at +10240 (per-instruction), while
// a whole transaction may grow accounts by up to 20 MiB across all its
// instructions. Mirrors the same value already defined at
// `vex_svm/block_produce.zig:339` and `vex_svm/voteforge/account_io.zig:56`;
// those modules layer above `vex_bpf2` and cannot import this one, so the value
// is carried by comment cross-reference rather than a shared symbol.
pub const MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION: u64 = 10 * 1024 * 1024 * 2; // 20 MiB

// ── Errors ────────────────────────────────────────────────────────────────────
//
// Brief specifies the union { AccessViolation, OutOfBounds }. Agave uses
// `AccessViolation` + `StackAccessViolation`; we surface the latter through
// the executor (it owns version + max_call_depth context) and keep this layer
// to the two errors the spec defines. `OutOfBounds` is reserved for the
// allocator/init failure modes the M2 brief calls out (overlap, gap-not-power-
// of-two, etc.) — see init() callers.
pub const AccessError = error{ AccessViolation, OutOfBounds };

pub const MemoryRegionAccess = enum {
    load,
    store,
    exec,

    pub inline fn isWrite(self: MemoryRegionAccess) bool {
        return self == .store;
    }
};

// ── Region ────────────────────────────────────────────────────────────────────
//
// Mirrors agave `MemoryRegion` (memory_region.rs:42-58).
// Differences from agave (intentional, with reasoning):
//   1. We hold a Zig slice (`host: []u8`) instead of a raw `host_addr: u64 +
//      len: u64`. This lets the borrow-checker enforce lifetimes at compile
//      time without sacrificing performance — `host.ptr/host.len` lower to the
//      same two-word value agave uses.
//   2. Gap encoding stores `frame_size` and `gap_size` literally, NOT a
//      `vm_gap_shift` derived bit-position. The sBPF spec only uses gapped
//      mode for the V0/V1 stack where frame_size == gap_size and both are a
//      power of two; the spec brief asks for plain field semantics so the
//      executor can pass `STACK_FRAME_SIZE` directly without log2 math, and
//      so the math is auditable without `1 << shift` puzzles.
//   3. Brief dictates the public field set; we expose `is_writable` (bool)
//      where agave uses `writable: bool`. Same semantics.
pub const Region = struct {
    /// Inclusive start in VM virtual address space.
    vm_addr: u64,

    /// Backing host slice. ALWAYS a writable slice at the type level so we
    /// can support fast-path stores without re-translating; runtime writes are
    /// gated by `is_writable`. Read-only regions are constructed from a
    /// `[]const u8` via `fromConst()`, which `@constCast`s the pointer and
    /// flips `is_writable` to false — any attempt to write through it returns
    /// AccessViolation BEFORE the host pointer is dereferenced.
    host: []u8,

    is_writable: bool,

    /// Frame size for gapped regions (== STACK_FRAME_SIZE on V0/V1 stack).
    /// Zero for flat regions.
    frame_size: u64 = 0,

    /// Gap size for gapped regions (== STACK_FRAME_SIZE on V0/V1 stack).
    /// Zero for flat regions.
    gap_size: u64 = 0,

    /// Construct a flat writable region from a `[]u8`.
    /// agave: `MemoryRegion::new_writable` (memory_region.rs:90-92)
    pub fn fromSlice(vm_addr: u64, buf: []u8) Region {
        return .{
            .vm_addr = vm_addr,
            .host = buf,
            .is_writable = true,
        };
    }

    /// Construct a flat read-only region from a `[]const u8`.
    /// agave: `MemoryRegion::new_readonly` (memory_region.rs:85-87)
    pub fn fromConst(vm_addr: u64, buf: []const u8) Region {
        return .{
            .vm_addr = vm_addr,
            .host = @constCast(buf),
            .is_writable = false,
        };
    }

    /// Construct a writable gapped region (V0/V1 stack — vex-152m).
    /// agave: `MemoryRegion::new_writable_gapped` (memory_region.rs:95-97)
    ///
    /// Layout:
    ///     guest:  [frame 0][ gap 0 ][frame 1][ gap 1 ]…
    ///     host:   [frame 0][frame 1][frame 2]…
    /// Each guest stride covers `frame_size + gap_size` virtual bytes but
    /// only `frame_size` host bytes; accessing within a gap returns
    /// AccessViolation.
    ///
    /// In agave the gap is encoded as a power-of-two shift; here we keep
    /// frame_size + gap_size as literal fields. We require gap_size to equal
    /// frame_size (this is the only configuration agave actually uses) and
    /// to be a power of two — this preserves the bitwise math agave relies on
    /// for V0 program parity. See vex-152m / fix_ledger.md.
    pub fn initGapped(vm_addr: u64, buf: []u8, frame_size: u64) Region {
        std.debug.assert(frame_size > 0);
        // power-of-two — required so the executor’s frame-index math
        // (computed against STACK_FRAME_SIZE) stays bit-exact with agave.
        std.debug.assert((frame_size & (frame_size - 1)) == 0);
        return .{
            .vm_addr = vm_addr,
            .host = buf,
            .is_writable = true,
            .frame_size = frame_size,
            .gap_size = frame_size,
        };
    }

    pub inline fn isGapped(self: Region) bool {
        return self.gap_size > 0;
    }

    /// End of the virtual address range covered by this region.
    /// Flat:    vm_addr + host.len
    /// Gapped:  vm_addr + host.len * 2 (each frame paired with a gap)
    pub inline fn vmEnd(self: Region) u64 {
        const stride: u64 = if (self.isGapped()) 2 else 1;
        return self.vm_addr +| (self.host.len * stride);
    }

    /// Translate a VM address+length to a host slice.
    ///
    /// Mirrors agave `MemoryRegion::vm_to_host` (memory_region.rs:108-136)
    /// adapted to the literal frame/gap encoding.
    ///
    /// vex-152n2 contract: `vm_addr < self.vm_addr` MUST be checked BEFORE
    /// the subtraction. A naive `vm_addr - self.vm_addr` would wrap on
    /// u64 and produce a colossal positive offset that may then pass the
    /// `end_offset <= len` check in surprising ways. Tested below.
    pub fn translate(
        self: Region,
        vm_addr: u64,
        len: u64,
        acc: MemoryRegionAccess,
    ) AccessError![]u8 {
        // RO check (agave memory_region.rs:110-112)
        if (acc.isWrite() and !self.is_writable) return AccessError.AccessViolation;

        // vex-152n2 underflow guard — BEFORE any subtraction.
        if (vm_addr < self.vm_addr) return AccessError.AccessViolation;

        const begin_offset: u64 = vm_addr - self.vm_addr;

        if (self.isGapped()) {
            // ── Gapped translation (vex-152m) ────────────────────────────
            // Stride = frame + gap. Position within the stride decides
            // whether we’re in the live frame or in the dead gap.
            const stride: u64 = std.math.add(u64, self.frame_size, self.gap_size) catch
                return AccessError.AccessViolation;
            // stride > 0 (frame_size asserted > 0 in initGapped)
            const off_in_stride: u64 = begin_offset % stride;
            if (off_in_stride >= self.frame_size) return AccessError.AccessViolation;

            const frame_idx: u64 = begin_offset / stride;
            // Guard the multiply: a garbage VA can produce a `begin_offset`
            // large enough that `frame_idx * frame_size` overflows u64. The
            // adjacent `add` calls below already use `std.math.add`; this
            // mirrors that for the only remaining unchecked arithmetic on
            // the gapped path (panic at interpreter.zig:914 → load → here,
            // observed in PID 975521 catch-up slot 9 on tx f786e59c).
            const host_off_mul = std.math.mul(u64, frame_idx, self.frame_size) catch
                return AccessError.AccessViolation;
            const host_off: u64 = std.math.add(u64, host_off_mul, off_in_stride) catch
                return AccessError.AccessViolation;
            const end: u64 = std.math.add(u64, host_off, len) catch
                return AccessError.AccessViolation;
            // agave memory_region.rs:109-134 (MemoryRegion::vm_to_host) and FD
            // fd_vm_private.h:442-489 (fd_vm_mem_haddr) do NOT reject an access
            // whose length runs past the CURRENT frame into the following gap,
            // as long as the START addr isn't itself in a gap (off_in_stride >=
            // self.frame_size, checked above) and the compacted host end stays
            // within the region's physical buffer (end > self.host.len, below).
            // VM-space gaps have no physical counterpart to violate; the prior
            // non-canonical `off_in_stride + len > self.frame_size` guard here
            // rejected legitimate multi-frame-spanning stack memcpy/memmove that
            // Agave allows (conformance fixture memcpy/..._1443524.fix: dst=stack
            // vaddr+0, n=5001 > STACK_FRAME_SIZE=4096, sbpf v0). Backported from
            // zbpf 3451e50 (2026-07-18).
            if (end > self.host.len) return AccessError.AccessViolation;
            return self.host[host_off..end];
        } else {
            // ── Flat translation (agave fast path) ───────────────────────
            const end: u64 = std.math.add(u64, begin_offset, len) catch
                return AccessError.AccessViolation;
            if (end > self.host.len) return AccessError.AccessViolation;
            return self.host[begin_offset..end];
        }
    }
};

// ── AlignedMemoryMap ──────────────────────────────────────────────────────────
//
// Mirrors agave `AlignedMemoryMapping` (memory_region.rs:348-449).
// Region selection by upper VIRTUAL_ADDRESS_BITS bits — O(1).
// We reserve the brief’s direct-mapping path as a dormant Config bool —
// see `Config.direct_mapping` doc-comment below for the testnet feature
// gate status.

pub const Config = struct {
    /// SIMD-0460 virtual_address_space_adjustments. When true, `vmap()` routes
    /// INPUT_REGION accesses through `findInputMemRegion` (per-account regions
    /// with per-region is_writable). When false, the single-flat-region MODE 1
    /// path is used. PR-3 wires this through from `v2_dispatch.zig` reading
    /// `InvokeContext.vasa_active`.
    virtual_address_space_adjustments: bool = false,
    /// Direct mapping (sBPF v4 / SIMD-0257).
    ///   7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz   ACTIVE on testnet (SIMD-0460)
    ///   CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE  ACTIVE on testnet (SIMD-0257)
    /// PR-1 plumbing routes the feature-set bits onto InvokeContext but force-
    /// overrides them off via `SIMD_PORT_FORCE_OFF_VASA` / `SIMD_PORT_FORCE_OFF_DIRECT_MAPPING`
    /// in invoke_ctx.zig. PR-2 added the data structures. PR-3 wires vasa
    /// through vmap() — when this is true the resolver is live. DM (this
    /// field) remains stubbed via AccessViolation until PR-5.
    direct_mapping: bool = false,
};

// ── PR-2 (SIMD-0460 vasa) input-region structures ─────────────────────────────
// Ports Firedancer's `fd_vm_input_region_t` (fd_vm.h:25-33) and
// `fd_vm_acc_region_meta_t` (fd_vm.h:39-58). Dark code in PR-2 — only exercised
// once PR-3 lifts `SIMD_PORT_FORCE_OFF_VASA` in invoke_ctx.zig and routes the
// vmap() input-region branch through the resolver below.

/// One contiguous slice of host memory inside the larger input region.
/// In MODE 1 (vasa off, today's behavior) the entire input region is a single
/// `InputMemRegion`. In MODE 2/3 each non-loader-v1 account contributes two
/// regions (metadata + data+realloc) and `address_space_reserved` may exceed
/// `region_sz` so the OOB handler can grow `region_sz` mid-execution.
pub const InputMemRegion = struct {
    /// Offset from the start of the input region in VM address space.
    vaddr_offset: u64,
    /// Host pointer (raw `[*]u8` so this struct is plain-data; AlignedMemoryMap
    /// holds the backing slice and lifetime).
    haddr: [*]u8,
    /// Current size of the region (may grow via OOB handler when DM is enabled).
    region_sz: u32,
    /// Maximum size — caps in-place growth in `handleInputMemRegionOob`.
    address_space_reserved: u64,
    /// `false` short-circuits OOB growth and triggers an access-violation on
    /// stores to this region.
    is_writable: bool,
    /// Index into `acc_region_metas[]`; ignored when the region isn't backed
    /// by a per-account meta entry.
    acc_region_meta_idx: u64,
    /// DIAG (VEX_JITO_PROBE, 2026-06-07): set true by findInputMemRegion when a
    /// WRITE translates into this region. Read at commit to settle the JITO
    /// in-place write-drop carrier's (b')/(c) axis. Default false; zero cost.
    wrote: bool = false,
};

/// Per-account metadata that maps an instruction-account index to its
/// `InputMemRegion`. Holds the expected vm-addresses of the serialized
/// pubkey/lamports/owner/data fields for CPI pointer-equality checks
/// (Firedancer `from_account_info` at cpi_common.c:329-336).
pub const AccRegionMeta = struct {
    region_idx: u32,
    /// Pre-resize data length; used by the non-DM code path which must report
    /// the original-len even after growth. Per Firedancer comment this is
    /// removable post-DM activation; we keep it to mirror the byte layout.
    original_data_len: u64,
    /// Pointer to the underlying account meta in the TransactionContext.
    /// `?*anyopaque` to preserve the leaf-module invariant; concrete type
    /// resolved by callers (cpi.zig + serialize.zig).
    meta_opaque: ?*anyopaque = null,
    /// CPI pointer-equality reference addresses (zero until the serializer
    /// emits a MODE 2/3 layout).
    vm_addr: u64 = 0,
    vm_key_addr: u64 = 0,
    vm_lamports_addr: u64 = 0,
    vm_owner_addr: u64 = 0,
    vm_data_addr: u64 = 0,
};

/// Binary search for the input-region whose `[vaddr_offset, vaddr_offset+address_space_reserved)`
/// contains `offset`. Mirrors Firedancer's `fd_vm_get_input_mem_region_idx`
/// (fd_vm_private.h:302-317).
///
/// Callers are responsible for validating the returned index — when `offset`
/// is past every region's reserved upper bound, this returns `regions.len-1`
/// (the upper-most region), and the caller MUST detect the out-of-bounds in
/// a follow-up size check.
pub fn getInputMemRegionIdx(regions: []const InputMemRegion, offset: u64) usize {
    if (regions.len == 0) return 0; // caller must check
    var left: usize = 0;
    var right: usize = regions.len - 1;
    while (left < right) {
        const mid = (left + right) / 2;
        const upper = regions[mid].vaddr_offset + regions[mid].address_space_reserved;
        if (offset >= upper) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return left;
}

/// `fd_vm_handle_input_mem_region_oob` port (fd_vm_private.h:324-387).
/// When a write hits offset past `region_sz` but within `address_space_reserved`,
/// bump `region_sz` to satisfy the write and track the growth in
/// `accounts_resize_delta` against the cumulative per-tx budget
/// (MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 20 MiB). The per-INSTRUCTION
/// +10240 cap (MAX_PERMITTED_DATA_INCREASE) is enforced separately via
/// `address_space_reserved`; the two caps are distinct.
///
/// Differences from Firedancer's full version (intentionally simpler):
/// - Does NOT touch the underlying BorrowedAccount meta (no setDataLength call).
///   That's handled separately by sol_set_data_length syscall when the BPF
///   program explicitly requests a length change. Direct memory writes past
///   `region_sz` are uncommon (legacy programs only); for those, bumping
///   region_sz is sufficient for the VM to translate subsequent reads, while
///   the syscall path keeps the consensus-affecting account meta in sync.
/// - Does NOT cap by FD_RUNTIME_ACC_SZ_MAX (10 MiB) — our address_space_reserved
///   already caps at dlen + 10 KiB, so this is implicit.
/// PR-5w (2026-05-19) — type-erased callback that grows the underlying
/// `acct.data` slice for a given account index. Returns the new data pointer
/// on success or null on allocation failure. Mirrors Agave's
/// `access_violation_handler` resize step (transaction.rs:535-541): `account.
/// resize(new_len, 0)` followed by `region.host_addr = data.as_mut_ptr()`.
///
/// Carrier closed: GJHt-class MODE 3 output-byte mismatch. Pre-PR-5w the OOB
/// handler grew `region_sz` lazily but `region.haddr` still pointed at the
/// original `acct.data.ptr` allocation (sized exactly `dlen`, no slack — see
/// v2_dispatch.zig:306,325,540). BPF writes past `dlen` landed in heap-
/// adjacent memory and the `@min(out.data_len, acct_data.len)` clamp at
/// v2_dispatch.zig:1125 then discarded them on commit — silently divergent
/// from cluster which calls `set_data_length(post_len)`.
pub const ReallocFn = *const fn (ctx: *anyopaque, acct_idx: u64, new_len: usize) ?[*]u8;

pub fn handleInputMemRegionOob(
    region: *InputMemRegion,
    offset: u64,
    sz: u64,
    write: bool,
    virtual_address_space_adjustments: bool,
    /// Per-tx growth-delta tracker (consensus-affecting). Null when not wired
    /// (PR-2 tests pass null). When non-null, must be backed by the
    /// TransactionContext's `accounts_resize_delta` field.
    accounts_resize_delta: ?*i64,
    /// PR-5w: realloc callback. When non-null AND this region is an account
    /// data region (acc_region_meta_idx != maxInt), the handler will realloc
    /// the underlying account's data slice and update `region.haddr` so
    /// subsequent writes within `address_space_reserved` land inside the
    /// extended canonical buffer rather than heap-adjacent memory.
    realloc_fn: ?ReallocFn,
    realloc_ctx: ?*anyopaque,
) void {
    if (!virtual_address_space_adjustments) return;
    if (!write) return;
    if (!region.is_writable) return;

    // requested_len = bytes from region start to end of access.
    const requested_len = std.math.add(u64, std.math.sub(u64, offset, region.vaddr_offset) catch return, sz) catch return;
    if (requested_len > region.address_space_reserved) return;

    // Remaining CUMULATIVE per-TRANSACTION growth budget (20 MiB, Agave
    // MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION). The per-INSTRUCTION +10240 cap is
    // enforced separately and structurally by `address_space_reserved`
    // (= original_data_len + MAX_PERMITTED_DATA_INCREASE, set at serialize.zig:607)
    // via the `requested_len > region.address_space_reserved` early-return above
    // and the `new_region_sz = min(address_space_reserved, region_sz + remaining)`
    // clamp below — so this budget bounds only the transaction-wide sum, never a
    // single realloc. (Was erroneously 10240 = the per-instruction value, which
    // collapsed the two caps into one and silently truncated multi-realloc
    // grow transactions; carrier @slot 421724293, epoch-989 bank-hash divergence.)
    const MAX_GROWTH_PER_TX: u64 = MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION;
    const used: i64 = if (accounts_resize_delta) |p| p.* else 0;
    const remaining: u64 = if (used >= 0)
        if (@as(i64, MAX_GROWTH_PER_TX) > used) @intCast(@as(i64, MAX_GROWTH_PER_TX) - used) else 0
    else
        MAX_GROWTH_PER_TX + @as(u64, @intCast(-used)); // shrink frees budget

    // new_region_sz = min(reserved, region_sz + remaining). Matches Firedancer's
    // lazy growth strategy (fd_vm_private.h:371-373).
    //
    // NOTE: this OOB path only fires when the program STORES past region_sz.
    // A header-only realloc (SDK realloc with zero_init=false and no store into
    // the extension) writes only the serialized dlen field and never reaches
    // this handler — that case is committed by the DM writeback grow in
    // v2_dispatch.zig (post_len_dm > canon.data.len branch), which mirrors
    // Agave set_data_length. That writeback grow was the epoch-989 carrier
    // (slot 421724293); this budget constant alone did NOT bind for it.
    //
    // TODO(residual-parity, per-tx budget overflow): when `remaining` hits 0
    // because the cumulative per-tx growth would exceed 20 MiB, Agave FAILS the
    // instruction with `InstructionError::MaxAccountsDataAllocationsExceeded`
    // (transaction-context/src/transaction_accounts.rs:314 `can_data_be_resized`).
    // Vexor instead REFUSES the growth here (region_sz unchanged). On the direct-
    // memory-write realloc path that refusal surfaces one frame up as
    // `AccessError.AccessViolation` (findInputMemRegion re-checks bounds and the
    // write no longer fits) → the instruction still fails, so account state and
    // fee outcome match Agave and the bank_hash is unaffected — only the surfaced
    // error *code* differs. On the header-only path the writeback grow likewise
    // refuses over-budget growth and falls back to the clamp — a residual
    // divergence, but UNREACHABLE on real traffic: hitting the 20 MiB per-tx sum
    // requires >2048 reallocs of +10240 in one transaction, which the CU budget
    // and 1232-byte tx size limit make impossible. Implementing the canonical
    // error is deferred because it requires threading an InstructionError out of
    // this `void`-returning handler through the hot writeback path (invasive,
    // >60 LoC, touches consensus commit). Boundary is pinned by the
    // "per-tx budget" KATs in memory_test.zig.
    const cap_a = region.address_space_reserved;
    const cap_b = std.math.add(u64, region.region_sz, remaining) catch region.address_space_reserved;
    const new_region_sz: u64 = @min(cap_a, cap_b);

    if (new_region_sz > region.region_sz) {
        const growth: u64 = new_region_sz - region.region_sz;
        if (accounts_resize_delta) |p| {
            p.* = std.math.add(i64, p.*, @intCast(growth)) catch p.*;
        }
        // PR-5w (2026-05-19): mirror Agave transaction.rs:535-541. If this is
        // an account data region (acc_region_meta_idx != maxInt) and we have
        // a realloc callback, grow the canonical `acct.data` buffer AND
        // update `region.haddr` so the BPF VM's write at the new offset
        // lands inside the actual buffer (not heap-adjacent memory). If
        // realloc fails, region_sz grows but haddr stays stale — falls back
        // to pre-PR-5w behavior (silently divergent but not crashing).
        if (region.acc_region_meta_idx != std.math.maxInt(u64)) {
            if (realloc_fn) |rf| {
                if (realloc_ctx) |rc| {
                    if (rf(rc, region.acc_region_meta_idx, @intCast(new_region_sz))) |new_ptr| {
                        region.haddr = new_ptr;
                    }
                }
            }
        }
        region.region_sz = @intCast(new_region_sz);
    }
}

/// Top-level input-region resolver mirroring Firedancer's
/// `fd_vm_find_input_mem_region` (fd_vm_private.h:395-437). Translates an
/// `(offset, sz, write)` triple into an `[]u8` host slice (or AccessError).
pub fn findInputMemRegion(
    regions: []InputMemRegion,
    metas: []const AccRegionMeta,
    offset: u64,
    sz: u64,
    write: bool,
    /// Passed-through to the OOB handler.
    virtual_address_space_adjustments: bool,
    /// Per-tx growth budget tracker. Null when not wired (test paths).
    accounts_resize_delta: ?*i64,
    /// PR-5w realloc callback — passed through to the OOB handler. Null in
    /// test paths.
    realloc_fn: ?ReallocFn,
    realloc_ctx: ?*anyopaque,
) AccessError![]u8 {
    _ = metas;
    if (regions.len == 0) return AccessError.AccessViolation;

    const region_idx = getInputMemRegionIdx(regions, offset);
    if (region_idx >= regions.len) return AccessError.AccessViolation;

    const region_ptr = &regions[region_idx];
    var bytes_in_region: u64 = std.math.sub(u64, region_ptr.region_sz, std.math.sub(u64, offset, region_ptr.vaddr_offset) catch return AccessError.AccessViolation) catch 0;

    if (sz > bytes_in_region) {
        handleInputMemRegionOob(region_ptr, offset, sz, write, virtual_address_space_adjustments, accounts_resize_delta, realloc_fn, realloc_ctx);
        // Re-check bounds after the OOB handler.
        bytes_in_region = std.math.sub(u64, region_ptr.region_sz, std.math.sub(u64, offset, region_ptr.vaddr_offset) catch return AccessError.AccessViolation) catch 0;
        if (sz > bytes_in_region) return AccessError.AccessViolation;
    }

    if (write and !region_ptr.is_writable) return AccessError.AccessViolation;

    const adjusted = std.math.sub(u64, offset, region_ptr.vaddr_offset) catch return AccessError.AccessViolation;
    const start: usize = @intCast(adjusted);
    const end: usize = @intCast(std.math.add(u64, adjusted, sz) catch return AccessError.AccessViolation);
    // DIAG (VEX_JITO_PROBE, 2026-06-08): mark this region as written when a
    // STORE access fully translates into it. This is the DM-mode store
    // chokepoint (interpreter Vm.store -> mm.vmap(.store) -> here with
    // write=true), and `regions` is the SAME mm.input_mem_regions slice read
    // at commit (v2_dispatch:1304). Read at commit to settle the JITO in-place
    // write-drop carrier's (b')/(c) axis: did the VM actually issue a store for
    // the dropped PDAs? Zero cost on the read path (write-only branch).
    if (write) region_ptr.wrote = true;
    return region_ptr.haddr[start..end];
}

pub const AlignedMemoryMap = struct {
    /// Owned, allocator-backed copy of the regions list. Agave uses a sorted
    /// `Box<[MemoryRegion]>` indexed at `vm_addr >> VIRTUAL_ADDRESS_BITS`.
    /// We do the same; max useful index in production is 5 (input region),
    /// but we leave the list size dynamic to avoid baking the layout into
    /// this file (M3+ will set the count).
    regions: []Region,
    /// PR-2 (SIMD-0460 vasa) — owned input-region fragments. Empty in MODE 1
    /// (the existing single-flat-region path stays via `regions[INPUT_REGION_IDX]`).
    /// PR-3 will populate this with per-account regions when the vasa feature
    /// is active, at which point `vmap()` switches its input-region branch
    /// to consult `findInputMemRegion(input_mem_regions, acc_region_metas, ...)`.
    /// Caller (serializer) owns lifetime; `deinit` frees the slice.
    input_mem_regions: []InputMemRegion = &.{},
    /// PR-2 (SIMD-0460 vasa) — per-account-index metadata enabling CPI pointer-
    /// equality checks. Indexed by instruction-account index. Empty until PR-3.
    acc_region_metas: []AccRegionMeta = &.{},
    /// PR-3.5 (vasa OOB handler) — pointer into TransactionContext's
    /// `accounts_resize_delta` field. When non-null AND vasa is active, the OOB
    /// handler in handleInputMemRegionOob bumps this on legitimate growth and
    /// caps cumulative growth at the per-tx budget
    /// (MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 20 MiB).
    accounts_resize_delta_ptr: ?*i64 = null,
    /// PR-5w (2026-05-19) — realloc callback for OOB grow path. When non-null
    /// and accompanied by `realloc_ctx`, the OOB handler will resize the
    /// canonical account data buffer (mirroring Agave transaction.rs:541)
    /// when a write extends an account-data region beyond its current size
    /// but within `address_space_reserved`. Null = pre-PR-5w behavior (grow
    /// region_sz only; haddr stays at original `acct.data.ptr`, writes past
    /// dlen land in heap-adjacent memory).
    realloc_fn: ?ReallocFn = null,
    realloc_ctx: ?*anyopaque = null,
    allocator: std.mem.Allocator,
    config: Config,

    pub fn init(
        allocator: std.mem.Allocator,
        regions: []const Region,
    ) (error{OutOfMemory} || AccessError)!AlignedMemoryMap {
        return initWithConfig(allocator, regions, .{});
    }

    pub fn initWithConfig(
        allocator: std.mem.Allocator,
        regions: []const Region,
        config: Config,
    ) (error{OutOfMemory} || AccessError)!AlignedMemoryMap {
        // agave (memory_region.rs:392-404): each region’s vm_addr upper-bits
        // index must equal its position in the sorted list. We require the
        // caller to pass them in order (executor builds in canonical order:
        // bytecode, rodata, stack, heap, input), which lets us validate in
        // a single pass without an in-place sort.
        for (regions, 0..) |r, idx_usize| {
            const idx = r.vm_addr >> VIRTUAL_ADDRESS_BITS;
            if (idx != idx_usize) return AccessError.OutOfBounds;
        }
        const owned = try allocator.dupe(Region, regions);
        return .{
            .regions = owned,
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *AlignedMemoryMap) void {
        self.allocator.free(self.regions);
        self.regions = &.{};
        // PR-2 (SIMD-0460 vasa) — free input-region slices when they're owned.
        if (self.input_mem_regions.len > 0) {
            self.allocator.free(self.input_mem_regions);
            self.input_mem_regions = &.{};
        }
        if (self.acc_region_metas.len > 0) {
            self.allocator.free(self.acc_region_metas);
            self.acc_region_metas = &.{};
        }
    }

    /// Map a VM range to a host slice. Single fast-path; on miss it falls
    /// through to the generic access-violation generator.
    /// agave: `MemoryMapping::map` + `AlignedMemoryMapping::find_region`
    /// (memory_region.rs:418-429, 513-526).
    pub fn vmap(
        self: *AlignedMemoryMap,
        acc: MemoryRegionAccess,
        vm_addr: u64,
        len: u64,
    ) AccessError![]u8 {
        // PR-5h2 (2026-05-18): the prior "DORMANT" early-return for
        // direct_mapping returned AccessViolation on every vmap call when
        // SIMD-0257 was active — that's why PR-5h (eb8e471) blew up to
        // 0.71% parity on testnet: 14,169 AccessViolations across the
        // 2000-slot window broke every BPF program's writes. The actual
        // wire is the VASA branch below: serializer (serialize.zig:571)
        // already sets `region.haddr = @constCast(acct.data.ptr)` in MODE
        // 3 so findInputMemRegion returns a writable slice INTO the
        // direct-mapped account data. Non-input regions (heap/stack/
        // rodata/text) don't participate in direct mapping — they're
        // resolved by the per-region translate() at the bottom of this
        // function as before. ADDM ⊃ VASA on testnet (both flip together
        // per cluster activation schedule); the serializer reflects this
        // dependency (serialize.zig:540 `dm = cfg.account_data_direct_mapping`
        // is only consulted inside the `if (vasa)` block at line 526).
        // So when direct_mapping is on, input_mem_regions is populated
        // and the VASA branch always handles input accesses.

        const idx_u64 = vm_addr >> VIRTUAL_ADDRESS_BITS;
        if (idx_u64 >= self.regions.len) return AccessError.AccessViolation;
        const idx: usize = @intCast(idx_u64);

        // PR-3 (SIMD-0460 vasa) / PR-5h2 (SIMD-0257 ADDM): when vasa OR
        // direct_mapping is active and the access targets the INPUT region,
        // dispatch to the per-account-region resolver instead of the
        // single-region translate(). Enforces per-region is_writable
        // (catches stores to RO-account data which MODE 1 silently allowed)
        // and is the load-bearing wire onto cluster's MODE 2/3 path.
        const is_input_region = (vm_addr >= MM_INPUT_START) and (vm_addr < MM_INPUT_START + MM_REGION_SIZE);
        const use_region_resolver = (self.config.virtual_address_space_adjustments or self.config.direct_mapping) and is_input_region and self.input_mem_regions.len > 0;
        if (use_region_resolver) {
            const offset = vm_addr - MM_INPUT_START;
            const is_write = acc.isWrite();
            return findInputMemRegion(
                self.input_mem_regions,
                self.acc_region_metas,
                offset,
                len,
                is_write,
                self.config.virtual_address_space_adjustments,
                self.accounts_resize_delta_ptr,
                self.realloc_fn,
                self.realloc_ctx,
            );
        }

        const region = self.regions[idx];
        return region.translate(vm_addr, len, acc);
    }
};
