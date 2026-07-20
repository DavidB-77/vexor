//! Vexor BPF input-region serializer (vex_bpf2 / M5).
//!
//! @prov:bpf.serialize-map — spec-for-spec rebuild of Agave's ABIv1 parameter
//! serializer; full upstream line-map in PROVENANCE.md.
//!
//! Byte-output is held EQUAL to the existing serializer in
//!   src/vex_bpf/sbpf_executor.zig::serialise()
//! which itself byte-matches the 18 FD golden fixtures (aligned, non-DM).
//!
//! ## Scope
//!
//!  * Implements ALL THREE ABIv1 base layouts gated by `SerializeConfig`:
//!    MODE 1 flat-buffer (single region; `virtual_address_space_adjustments
//!    =false`), MODE 2 vasa (per-account regions; SIMD-0460, ACTIVE on
//!    testnet), and MODE 3 vasa+dm (adds `account_data_direct_mapping`).
//!    SIMD-0449 (`direct_account_pointers`) is additionally golden-vector-
//!    gated on top of all three. The only unsupported combination is bare
//!    `account_data_direct_mapping=true` WITHOUT `virtual_address_space_
//!    adjustments=true` — invalid per Agave/FD (direct-mapping presupposes
//!    per-account regions) — which returns `error.NotImplemented`. See SIMD
//!    references below.
//!
//!  * Loader-v1 (legacy unaligned ABIv0) is NOT implemented here — Vexor's
//!    sBPF executor only services aligned loaders (v2/v3); ABIv0 has no
//!    testnet/mainnet relevance at the layer this module sits at.
//!
//! ## SIMD references
//!
//!  - SIMD-0449  (direct_account_pointers_in_program_input): a u64 marker-
//!    vm_addr array (one per instruction account incl dups) appended after
//!    program_id. IMPLEMENTED + golden-vector-gated on ALL base layouts (flat,
//!    vasa, vasa+dm). Feature gate: ptr9umikaeAS7ZBBp2fsfRhie16F1V2jCKA2y6gXNAK
//!    (rc.1 feature-set/src/lib.rs:1524). NOT yet active on testnet — `cfg.
//!    direct_account_pointers` is driven by the live feature set per-tx and is
//!    false until the cluster activates the gate.
//!
//!  - SIMD-0460  (virtual_address_space_adjustments): per-account memory
//!    regions instead of one flat region. ACTIVE on testnet (live MODE-PROBE
//!    vasa=true). Feature gate: 7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz.
//!    (Note: SIMD-0173 is sBPFv2 instruction encoding — different feature.)
//!
//!  - bpf_account_data_direct_mapping (no SIMD-NNNN tag — companion to 0460):
//!    zero-copy host->vm mapping of account data. Stubbed.
//!    Feature gate: CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE — dormant.
//!    (Note: SIMD-0186 is `formalize_loaded_transaction_data_size` — unrelated.)
//!
//!  - SIMD-0321  (vm-r2-instruction-data-pointer): r2 must equal the vaddr of
//!    the first byte of `ix_data` inside the input region (i.e. the address
//!    immediately after the u64 ix_data length prefix). The vaddr is exposed
//!    via the returned `instruction_data_offset` (host offset) — callers
//!    reconstruct it as `INPUT_START + instruction_data_offset`.
//!
//! ## Fix-ledger anchors
//!
//!  - vex-079    (BPF_ALIGN_OF_U128 = 8, NOT 16): trailing align pad after
//!               account data uses 8-byte units. Mirrored here in
//!               `BPF_ALIGN_OF_U128`.
//!  - vex-034 #3 (NON_DUP_MARKER = 0xFF, dup slot = 7-byte zero pad): mirrored
//!               in `NON_DUP_MARKER` and the duplicate write path.
//!  - MAX_REALLOC = 10 KiB (`MAX_PERMITTED_DATA_INCREASE`): zero-padded
//!               trailing slack after every account's data. @prov:bpf.serialize-map
//!  - rent_epoch = u64::MAX (mask_out_rent_epoch_in_vm_serialization): the
//!               last u64 per non-dup account is always `u64::MAX`, never the
//!               accountsdb-stored rent epoch. @prov:bpf.serialize-map
//!
//! ## Public surface
//!
//!  - `SerializeError`              error set
//!  - `SerializeConfig`             feature-gate config (defaults: testnet)
//!  - `AccountInput`                read input shape (matches sbpf_executor.AccountEntry)
//!  - `AccountOutput`               write-back shape used by deserializeReturn
//!  - `SerializedAccount`           per-account vm/host metadata (Agave-shaped)
//!  - `serializeParametersAligned`  ABIv1 flat-buffer path
//!  - `deserializeReturn`           post-execute write-back walk
//!  - `accountVaddr` / `accountSize` / `alignPadForLen`  helpers
//!
//! Any byte-level divergence from sbpf_executor.serialise() is a regression.
//! `serialize_test.zig` enforces 18-fixture byte-identity + cross-impl parity.

const std = @import("std");
const mem = @import("memory.zig");
const builtin = @import("builtin");

// ── Constants (mirroring Agave + locked Vexor invariants) ─────────────────────

/// Input region base virtual address (== `solana_sbpf::ebpf::MM_INPUT_START`).
/// Vexor pins the input buffer at this vaddr for the BPF VM.
pub const INPUT_START: u64 = 0x4_0000_0000;

/// Marker byte indicating a non-duplicate account at the start of its slot.
/// `0xFF` matches `solana_program_entrypoint::NON_DUP_MARKER`.
pub const NON_DUP_MARKER: u8 = 0xFF;

/// Per-account trailing slack reserved for in-VM realloc growth, in bytes.
/// Matches `solana_program_entrypoint::MAX_PERMITTED_DATA_INCREASE` (10 KiB).
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// Alias matching the FD/Vexor naming used in fix_ledger and existing code.
pub const MAX_REALLOC: usize = MAX_PERMITTED_DATA_INCREASE;

/// On-VM alignment of u128 (sBPF target makes `align_of::<u128>() == 8`,
/// even though many host machines use 16). vex-079 fix locks this to 8;
/// using 16 produces wrong-sized trailing padding and crashes BPF programs
/// that walk `account_info.data` at `BPF_ALIGN_OF_U128`-aligned offsets.
pub const BPF_ALIGN_OF_U128: usize = 8;

/// Host buffer alignment. @prov:bpf.serialize-map
/// Vexor allocates the input buffer with this alignment so the buffer's
/// start address satisfies BPF's host-side alignment expectations.
pub const HOST_ALIGN: std.mem.Alignment = .@"16";

/// Account-data ceiling — refusal threshold on deserialization realloc.
/// Matches `solana_system_interface::MAX_PERMITTED_DATA_LENGTH` (10 MiB).
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

// ── Error set ─────────────────────────────────────────────────────────────────

pub const SerializeError = error{
    /// Caller turned on a feature gate this rebuild does not implement
    /// (direct_account_pointers / virtual_address_space_adjustments /
    /// account_data_direct_mapping). Testnet keeps these off; turn them on
    /// only after the M-series fully wires the per-account-region path.
    NotImplemented,
    /// Buffer is too short to satisfy a structural read during deserialization.
    InvalidArgument,
    /// post_data_len exceeds pre_data_len + MAX_PERMITTED_DATA_INCREASE
    /// or absolute MAX_PERMITTED_DATA_LENGTH ceiling.
    InvalidRealloc,
    /// More than 256 instruction accounts; duplicate position cannot fit u8.
    /// @prov:bpf.serialize-map — Agave hits this earlier via `MaxAccountsExceeded` at 255.
    TooManyAccounts,
    OutOfMemory,
};

// ── Public input/output shapes ────────────────────────────────────────────────

/// One account as fed into the serializer. Field-for-field compatible with
/// `src/vex_bpf/sbpf_executor.zig::AccountEntry` so callers can reuse existing
/// types when wiring through the M8 invoke-context.
pub const AccountInput = struct {
    pubkey:      [32]u8,
    owner:       [32]u8,
    lamports:    u64,
    data:        []const u8,
    executable:  bool,
    /// Stored on disk. NEVER serialized into the input region — always write
    /// `u64::MAX` instead (mask_out_rent_epoch_in_vm_serialization). @prov:bpf.serialize-map
    rent_epoch:  u64,
    is_signer:   bool,
    is_writable: bool,
};

/// Output shape for `deserializeReturn` — the BPF program may have mutated
/// lamports/data/owner; this struct receives the post-execution view. The
/// caller pairs the slice 1:1 with the `accounts` slice it passed to
/// `serializeParametersAligned`.
pub const AccountOutput = struct {
    /// New lamports value read from the input region.
    lamports:  u64,
    /// New owner pubkey read from the input region.
    owner:     [32]u8,
    /// New data length read from the input region (already validated against
    /// MAX_PERMITTED_DATA_INCREASE). May be < or > `original_data_len`.
    data_len:  usize,
    /// Slice into the input buffer covering `data_len` bytes of post-exec data.
    /// The slice references `input_buf`, so it is valid only for the lifetime
    /// of the buffer the caller allocated for `serializeParametersAligned`.
    data:      []const u8,
};

/// Per-account metadata returned by `serializeParametersAligned`. @prov:bpf.serialize-map
/// so the M8 invoke-context can consume it directly without an adapter.
pub const SerializedAccount = struct {
    /// VM virtual address of this account's pubkey (`key`).
    vm_key_addr:      u64,
    /// VM virtual address of this account's owner pubkey.
    vm_owner_addr:    u64,
    /// VM virtual address of this account's u64 lamports field.
    vm_lamports_addr: u64,
    /// VM virtual address of the first data byte (after the u64 dlen prefix).
    vm_data_addr:     u64,
    /// Original `data.len()` at serialization time — required by
    /// `deserializeReturn` to compute the post-data offset.
    original_data_len: usize,
    /// Host buffer offset of the lamports u64 (used internally by
    /// `deserializeReturn`; exposed for diagnostics).
    host_lamports_offset: usize,
    /// Host buffer offset of the data slice's first byte.
    host_data_offset:     usize,
    /// Host buffer offset of the owner pubkey.
    host_owner_offset:    usize,
    /// `true` if this slot was written as a duplicate-of-earlier-account
    /// (1-byte position + 7 zero bytes); duplicates carry no per-account data
    /// in the input region and `deserializeReturn` must skip them.
    is_duplicate:         bool,
};

/// Feature-gate config. Defaults match testnet (everything off). Future
/// epochs that activate SIMD-0460 / bpf_account_data_direct_mapping /
/// SIMD-0449 will flip these on from the runtime feature set; this module
/// returns `error.NotImplemented` until the per-account-region path is wired.
pub const SerializeConfig = struct {
    /// SIMD-0460 (virtual_address_space_adjustments). Off → single flat
    /// region at INPUT_START. On → per-account regions interleaved with the
    /// boilerplate region. Feature gate:
    /// 7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz (dormant on testnet).
    virtual_address_space_adjustments: bool = false,
    /// bpf_account_data_direct_mapping (no SIMD-NNNN tag). Off → account
    /// data is COPIED into the input buffer. On → mapped zero-copy and the
    /// buffer holds only boilerplate. Requires
    /// `virtual_address_space_adjustments=true`. Feature gate:
    /// CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE (dormant on testnet).
    account_data_direct_mapping: bool = false,
    /// SIMD-0449. Off → input region ends at program_id. On → an array of
    /// per-account `vm_data_addr` u64s is appended (BPF_ALIGN_OF_U128 padded).
    direct_account_pointers: bool = false,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Trailing zero pad needed to bump `len` up to the next BPF_ALIGN_OF_U128
/// boundary. Used after each account's data + realloc slack so that the
/// next field (rent_epoch u64) sits on an 8-aligned host offset.
pub inline fn alignPadForLen(len: usize) usize {
    return (BPF_ALIGN_OF_U128 - (len % BPF_ALIGN_OF_U128)) % BPF_ALIGN_OF_U128;
}

/// Total in-buffer footprint of one **non-duplicate** account slot,
/// **including** the leading NON_DUP_MARKER byte:
///   1 NON_DUP + 1 signer + 1 writable + 1 exec + 4 zero-pad
/// + 32 key + 32 owner
/// + 8 lamports + 8 dlen
/// + data.len + (MAX_REALLOC + align_pad)
/// + 8 rent_epoch
/// = 96 + data.len + MAX_REALLOC + alignPadForLen(data.len)
pub inline fn accountSize(data_len: usize) u64 {
    const fixed: usize = 1 + 1 + 1 + 1 + 4 + 32 + 32 + 8 + 8 + 8;
    return @as(u64, @intCast(fixed + data_len + MAX_REALLOC + alignPadForLen(data_len)));
}

/// VM virtual address of the start of account slot `idx` within the buffer,
/// assuming all preceding accounts were written at `host_offset` `off`.
/// Provided for callers that want to compute vaddrs without retaining the
/// SerializedAccount slice; in practice the slice is the better source.
pub inline fn accountVaddr(host_offset: usize) u64 {
    return INPUT_START + @as(u64, @intCast(host_offset));
}

// ── Internal serializer state ─────────────────────────────────────────────────
//
// @prov:bpf.serialize-map (`Serializer` impl) but only retains the flat-buffer fields. The
// `regions`/`region_start` machinery is omitted because we don't push
// per-account regions in the supported path.

/// Cursor-style writer over a pre-allocated buffer. We pre-compute the exact
/// total size, alloc once, and write through a moving offset. This keeps
/// `bytes` a flat `[]u8` (not an ArrayList) and dodges the ArrayList-aligned
/// `toOwnedSlice`/`free` alignment-tracking dance — the VM consumer only
/// needs the byte content; the buffer's runtime alignment is the caller's
/// concern (M2 memory module pins it via posix_memalign in production).
const Inner = struct {
    buf: []u8,
    off: usize = 0,

    /// Append `data`, return its starting vm-vaddr.
    /// @prov:bpf.serialize-map — flat path.
    fn writeAll(self: *Inner, data: []const u8) u64 {
        const vaddr = INPUT_START + @as(u64, @intCast(self.off));
        @memcpy(self.buf[self.off .. self.off + data.len], data);
        self.off += data.len;
        return vaddr;
    }

    /// Append a `u8`/`u32`/`u64` little-endian primitive, return its vaddr.
    /// @prov:bpf.serialize-map
    fn writeInt(self: *Inner, comptime T: type, v: T) u64 {
        const vaddr = INPUT_START + @as(u64, @intCast(self.off));
        std.mem.writeInt(T, self.buf[self.off..][0..@sizeOf(T)], v, .little);
        self.off += @sizeOf(T);
        return vaddr;
    }

    /// @prov:bpf.serialize-map
    fn fillWrite(self: *Inner, n: usize, v: u8) void {
        @memset(self.buf[self.off .. self.off + n], v);
        self.off += n;
    }
};

// ── Size pre-calc ─────────────────────────────────────────────────────────── @prov:bpf.serialize-map

fn precomputeSize(
    accounts: []const AccountInput,
    ix_data:  []const u8,
    cfg:      SerializeConfig,
) usize {
    // 1) leading u64 account count
    var size: usize = 8;

    // 2) per-account contribution
    for (accounts, 0..) |acct, i| {
        size += 1; // dup marker / position byte
        const dup = findDuplicate(accounts, i);
        if (dup != null) {
            size += 7; // pad to 64-bit alignment of the next slot
            continue;
        }
        // Non-dup metadata header (constant in both MODE 2 and MODE 3):
        // is_signer + is_writable + executable + 4-byte zero pad +
        // key + owner + lamports + dlen
        size += 1 + 1 + 1 + 4 + 32 + 32 + 8 + 8;
        if (cfg.account_data_direct_mapping) {
            // SIMD-0257 MODE 3: data lives in the account's own storage; the
            // input region's data region's haddr points there directly. Buffer
            // gets only 8 bytes of FD_BPF_ALIGN_OF_U128 padding before the
            // next account's metadata. rent_epoch still 8 bytes.
            size += BPF_ALIGN_OF_U128 + 8;
        } else {
            // MODE 1/2: data + realloc slack + alignment pad live in buffer.
            size += acct.data.len + MAX_REALLOC + alignPadForLen(acct.data.len);
            size += 8; // rent_epoch
        }
    }

    // 3) ix_data prefix + bytes + program_id
    size += 8 + ix_data.len + 32;

    // 4) SIMD-0449 (direct_account_pointers): a BPF_ALIGN_OF_U128(=8)-aligned
    //    trailer of one u64 per instruction account (INCLUDING duplicates),
    //    each = that account's marker vm_addr. Verified byte-exact vs the rc.1
    //    golden vector: N == accounts.len (NOT the non-dup count). Added for
    //    BOTH the flat AND the vasa/vasa+dm paths — Agave reserves the trailer
    //    size unconditionally on vasa (serialization.rs:521) and the trailer
    //    write below (~:531) is likewise unconditional on vasa.
    //    ⚠ FOOTGUN: do NOT re-add an `and !vasa` guard here. `size` is the
    //    dm-aware BUFFER length; aligning on it matches Agave (which aligns on
    //    buffer length, :522) and — because the buffer/vaddr drift is provably
    //    ≡0 (mod 8) — also matches Firedancer's vm_addr alignment (:422). A
    //    `!vasa` guard would under-allocate under vasa → the `inner.off ==
    //    total_size` assert aborts OR the vasa trailing region truncates the
    //    trailer. Align on buffer length, never on vaddr_off.
    if (cfg.direct_account_pointers) {
        size += alignPadForLen(size) + accounts.len * 8;
    }
    return size;
}

/// First-occurrence pubkey match, returns `?u8` of the index of the earlier
/// account that this slot duplicates. @prov:bpf.serialize-map — semantically
/// equivalent, not API-shape (Vexor walks the slice rather than relying on
/// the transaction-context dedup map).
fn findDuplicate(accounts: []const AccountInput, i: usize) ?u8 {
    var j: usize = 0;
    while (j < i) : (j += 1) {
        if (std.mem.eql(u8, &accounts[j].pubkey, &accounts[i].pubkey)) {
            return @intCast(j);
        }
    }
    return null;
}

// ── Public: serialize ─────────────────────────────────────────────────────────

/// Result tuple returned by `serializeParametersAligned`.
pub const SerializeResult = struct {
    /// Heap-owned input buffer, 16-byte aligned. Caller frees with `alloc`.
    bytes:           []u8,
    /// One entry per account in `accounts`, 1:1 ordered. Caller frees with `alloc`.
    account_layouts: []SerializedAccount,
    /// Host offset of the first byte of `ix_data` (after the u64 dlen prefix).
    /// vaddr is `INPUT_START + instruction_data_offset` (SIMD-0321: r2 init).
    instruction_data_offset: usize,
    /// PR-3 (SIMD-0460 vasa) — partition of `bytes` into per-account regions.
    /// Empty when `cfg.virtual_address_space_adjustments=false` (MODE 1). When
    /// populated, contains 2 regions per non-duplicate account (metadata,
    /// data+realloc) plus a trailing region (rent_epoch + ix_info + program_id).
    /// Caller frees with the same `alloc`.
    input_regions:   []mem.InputMemRegion = &.{},
    /// PR-3 (SIMD-0460 vasa) — per-account-index metadata for CPI pointer-
    /// equality checks. Indexed by `accounts[i]` position. Duplicate accounts
    /// share the original's meta entry. Caller frees with `alloc`.
    acc_region_metas: []mem.AccRegionMeta = &.{},
};

/// Build the ABIv1 flat-buffer input region for an sBPF program invocation.
///
/// @prov:bpf.serialize-map — mirrors `serialize_parameters_for_abiv1`, flat-buffer
/// (single-region) path, which is the only path live on testnet today. See the
/// file-level comment for SIMD coverage.
///
/// On success, `bytes.ptr` is 16-byte aligned and `account_layouts.len ==
/// accounts.len`. Both slices are heap-owned by `alloc`.
pub fn serializeParametersAligned(
    alloc:      std.mem.Allocator,
    program_id: [32]u8,
    ix_data:    []const u8,
    accounts:   []const AccountInput,
    cfg:        SerializeConfig,
) SerializeError!SerializeResult {
    // PR-5 (SIMD-0257 ADDM): MODE 3 accepted when paired with vasa.
    // SIMD-0449 (direct_account_pointers) is a PURELY ADDITIVE trailer (N u64
    // marker vm_addrs, one per instruction account incl dups) appended after
    // program_id and absorbed by the existing trailing region. It composes with
    // EVERY base layout — flat (MODE 1), vasa (MODE 2), and vasa+dm (MODE 3) —
    // because the trailer values are `vm_key_addr − 8` and the vaddr space is
    // invariant across modes (the buffer/vaddr drift is provably ≡0 mod 8, so
    // buffer-length alignment == vm_addr alignment; Agave==Firedancer under dm).
    // The vasa+dm+0449 triple is the LIVE testnet regime once 0449 activates
    // (vasa+dm already active) and is gated by a real rc.1 golden vector
    // (serialize_test.zig "SIMD-0449 vasa+dm+0449"). Refs: agave rc.1
    // serialization.rs:520-583 (trailer size unconditional on vasa) +
    // fd_bpf_loader_serialization.c:419-434. DM without vasa is invalid per
    // Firedancer/Agave spec — that combination stays rejected below.
    if (cfg.account_data_direct_mapping and !cfg.virtual_address_space_adjustments) {
        return SerializeError.NotImplemented;
    }
    if (accounts.len > 255) return SerializeError.TooManyAccounts;

    // 1. Pre-allocate the buffer so writes never reallocate. The capacity must
    //    EXACTLY equal the final size (Agave debug-asserts this in `finish`).
    const total_size = precomputeSize(accounts, ix_data, cfg);

    const bytes = try alloc.alloc(u8, total_size);
    errdefer alloc.free(bytes);

    var inner = Inner{ .buf = bytes, .off = 0 };

    var layouts = try alloc.alloc(SerializedAccount, accounts.len);
    errdefer alloc.free(layouts);

    // 2. account count (u64 LE). @prov:bpf.serialize-map
    _ = inner.writeInt(u64, @as(u64, @intCast(accounts.len)));

    // PR-5 (SIMD-0257 ADDM): VM-space cursor for MODE 3 where buffer cursor
    // (inner.off) diverges from VM offset because data isn't in the buffer.
    // In MODE 1/2 this tracks inner.off exactly; in MODE 3 it advances by
    // `dlen + MAX_REALLOC` extra per non-duplicate account.
    var vaddr_off: u64 = inner.off;

    // 3. per-account slot
    for (accounts, 0..) |acct, i| {
        const dup_of = findDuplicate(accounts, i);
        if (dup_of) |pos| {
            // Duplicate slot: 1-byte position + 7 zero pad. @prov:bpf.serialize-map
            _ = inner.writeInt(u8, pos);
            inner.fillWrite(7, 0);
            vaddr_off += 8;
            // Mirror earlier slot's metadata. @prov:bpf.serialize-map
            layouts[i] = layouts[pos];
            layouts[i].is_duplicate = true;
            continue;
        }

        // Non-duplicate slot. @prov:bpf.serialize-map Header writes happen in
        // BOTH modes; metadata bytes are identical. vm_*_addr captures use
        // `vaddr_off` so MODE 3 multi-account layouts stay correct (inner.off
        // ≠ vaddr_off for accounts after the first in MODE 3).
        _ = inner.writeInt(u8, NON_DUP_MARKER);
        _ = inner.writeInt(u8, @intFromBool(acct.is_signer));
        _ = inner.writeInt(u8, @intFromBool(acct.is_writable));
        _ = inner.writeInt(u8, @intFromBool(acct.executable));
        // 4-byte zero pad. @prov:bpf.serialize-map
        _ = inner.writeInt(u32, 0);
        vaddr_off += 8; // marker + 3 flags + 4-byte pad

        const vm_key_addr: u64 = INPUT_START + vaddr_off;
        _ = inner.writeAll(&acct.pubkey);
        vaddr_off += 32;
        const host_owner_off = inner.off - 32; // for layout's `host_owner_offset` field
        _ = host_owner_off;

        const vm_owner_addr: u64 = INPUT_START + vaddr_off;
        _ = inner.writeAll(&acct.owner);
        vaddr_off += 32;
        const host_owner_off2 = inner.off - 32;

        const host_lam_off = inner.off;
        const vm_lam_addr: u64 = INPUT_START + vaddr_off;
        _ = inner.writeInt(u64, acct.lamports);
        vaddr_off += 8;

        _ = inner.writeInt(u64, @as(u64, @intCast(acct.data.len)));
        vaddr_off += 8; // dlen u64

        const host_data_off = inner.off;
        const vm_data_addr: u64 = INPUT_START + vaddr_off; // captured BEFORE data
        if (cfg.account_data_direct_mapping) {
            // PR-5 SIMD-0257 MODE 3: skip the dlen-byte data write AND the
            // realloc-slack zero-fill. Data lives in `acct.data`; the post-loop
            // region build sets the data region's haddr to acct.data.ptr. The
            // buffer just gets 8 zero bytes of BPF_ALIGN_OF_U128 padding.
            // @prov:bpf.serialize-map
            inner.fillWrite(BPF_ALIGN_OF_U128, 0);
            // VM space STILL advances by dlen + MAX_REALLOC (data region's
            // address_space_reserved) so subsequent vm_*_addr captures are
            // correct relative to cluster's VM layout.
            vaddr_off += acct.data.len + MAX_REALLOC;
            // Plus alignment that would have been pad; vaddr tracks the
            // implicit alignment slack. @prov:bpf.serialize-map
            vaddr_off += alignPadForLen(acct.data.len);
        } else {
            // MODE 1/2: data + realloc slack in buffer.
            _ = inner.writeAll(acct.data);
            const pad = alignPadForLen(acct.data.len);
            inner.fillWrite(MAX_REALLOC + pad, 0);
            vaddr_off += acct.data.len + MAX_REALLOC + pad;
        }
        // rent_epoch always = u64::MAX (mask_out_rent_epoch_in_vm_serialization).
        _ = inner.writeInt(u64, std.math.maxInt(u64));
        vaddr_off += 8;

        layouts[i] = .{
            .vm_key_addr      = vm_key_addr,
            .vm_owner_addr    = vm_owner_addr,
            .vm_lamports_addr = vm_lam_addr,
            .vm_data_addr     = vm_data_addr,
            .original_data_len    = acct.data.len,
            .host_lamports_offset = host_lam_off,
            .host_data_offset     = host_data_off,
            .host_owner_offset    = host_owner_off2,
            .is_duplicate         = false,
        };
    }

    // 4. ix_data prefix + bytes + program_id. @prov:bpf.serialize-map
    _ = inner.writeInt(u64, @as(u64, @intCast(ix_data.len)));
    const ix_off_host: usize = inner.off;
    _ = inner.writeAll(ix_data);
    _ = inner.writeAll(&program_id);

    // SIMD-0449 (direct_account_pointers_in_program_input): append, after the
    // program_id, a BPF_ALIGN_OF_U128(=8)-aligned array of one u64-LE per
    // instruction account (INCLUDING duplicates), each = that account's marker
    // vm_addr = INPUT_START + offset-of-its-NON_DUP_MARKER-byte. A duplicate
    // carries the ORIGINAL account's marker addr (its layout entry was cloned
    // above), matching rc.1 serialize_parameters_for_abiv1:575-583. The marker
    // addr == vm_key_addr - 8 (the 1+1+1+1+4 = 8-byte header preceding the key
    // is invariant in this path). Byte-exact vs the rc.1 golden vector — see
    // AGAVE-GOLDEN-VECTOR-HARNESS-2026-06-21.md. Inert unless the cfg bool is
    // set true by an active SIMD-0449 feature gate (every call site passes
    // false today → output byte-identical to baseline).
    if (cfg.direct_account_pointers) {
        inner.fillWrite(alignPadForLen(inner.off), 0);
        for (layouts) |layout| {
            _ = inner.writeInt(u64, layout.vm_key_addr - 8);
        }
    }

    // Hardening: total_size pre-calc must match what we wrote. Misalignments
    // here mean either precomputeSize() or the writer drifted.
    std.debug.assert(inner.off == total_size);

    // PR-3 (SIMD-0460 vasa): partition the flat buffer into per-account regions.
    // Bytes are identical to MODE 1 — vasa only changes how `vmap()` looks them
    // up. For each non-duplicate account: emit a metadata-region (always
    // writable) followed by a data+realloc region (writable iff
    // `acct.is_writable`). @prov:bpf.serialize-map — Duplicate slots
    // (8 bytes each) get folded into the next account's metadata region exactly
    // how the byte layout naturally has them.
    //
    // Region byte boundaries derived from the layout offsets we just captured:
    //   metadata-region : [curr_metadata_start, layout.host_data_offset)
    //   data-region     : [layout.host_data_offset, host_data_offset + dlen + MAX_REALLOC + align_pad)
    // Trailing region (rent_epoch + ix_data + program_id) is appended once at end.
    var input_regions_out: []mem.InputMemRegion = &.{};
    var acc_metas_out: []mem.AccRegionMeta = &.{};
    if (cfg.virtual_address_space_adjustments) {
        // 2N regions per non-dup account + 1 trailing region. Slightly over-
        // allocate to avoid a count pass — at most 2*N + 1 entries.
        var input_regions = std.ArrayListUnmanaged(mem.InputMemRegion){};
        errdefer input_regions.deinit(alloc);

        var acc_metas = try alloc.alloc(mem.AccRegionMeta, accounts.len);
        errdefer alloc.free(acc_metas);
        for (acc_metas) |*m| m.* = .{ .region_idx = 0, .original_data_len = 0 };

        // Dual cursors — host buffer (where bytes live) and vaddr (VM space).
        // Diverge in MODE 3 only; equal in MODE 2.
        var host_curr: usize = 0;
        var vaddr_curr: u64 = 0;
        const dm = cfg.account_data_direct_mapping;

        for (accounts, 0..) |acct, i| {
            const layout = layouts[i];
            if (layout.is_duplicate) {
                // Duplicate slot — 8 bytes already in the buffer (both modes).
                const dup_of = findDuplicate(accounts, i) orelse unreachable;
                acc_metas[i] = acc_metas[dup_of];
                continue;
            }

            // Metadata region — header+pubkey+owner+lamports+dlen u64.
            // Spans [host_curr .. layout.host_data_offset). vaddr_offset
            // uses vaddr_curr (== host_curr in MODE 2; diverges in MODE 3
            // after prior accounts' data regions consumed VM space).
            const metadata_sz = layout.host_data_offset - host_curr;
            try input_regions.append(alloc, .{
                .vaddr_offset = vaddr_curr,
                .haddr = @ptrCast(&bytes[host_curr]),
                .region_sz = @intCast(metadata_sz),
                .address_space_reserved = metadata_sz,
                .is_writable = true, // @prov:bpf.serialize-map
                .acc_region_meta_idx = std.math.maxInt(u64),
            });

            const dlen = layout.original_data_len;
            const data_reserved = dlen + MAX_REALLOC;
            // Data region — vaddr_offset advances by metadata_sz in both modes.
            // In MODE 2 haddr points into the buffer. In MODE 3 (DM) haddr
            // points DIRECTLY at the account's data slice (zero-copy).
            const data_vaddr = vaddr_curr + metadata_sz;
            const data_haddr: [*]u8 = if (dm)
                @constCast(acct.data.ptr)
            else
                @ptrCast(&bytes[layout.host_data_offset]);
            try input_regions.append(alloc, .{
                .vaddr_offset = data_vaddr,
                .haddr = data_haddr,
                .region_sz = @intCast(dlen),
                .address_space_reserved = data_reserved,
                .is_writable = acct.is_writable,
                .acc_region_meta_idx = i,
            });

            acc_metas[i] = .{
                .region_idx = @intCast(input_regions.items.len - 1),
                .original_data_len = dlen,
                .meta_opaque = null,
                .vm_addr = layout.vm_data_addr,
                .vm_key_addr = layout.vm_key_addr,
                .vm_lamports_addr = layout.vm_lamports_addr,
                .vm_owner_addr = layout.vm_owner_addr,
                .vm_data_addr = layout.vm_data_addr,
            };

            // Cursor advance:
            //   vaddr: metadata_sz + dlen + MAX_REALLOC (region's address_space_reserved)
            //   host MODE 2: same (data lives in buffer)
            //   host MODE 3: + (BPF_ALIGN_OF_U128 - alignPadForLen(dlen))
            //
            // The MODE 3 host_curr advance is subtle. The serializer wrote
            // BPF_ALIGN_OF_U128 = 8 zero bytes to the buffer for this
            // account's "data section" placeholder. But the NEXT region's
            // host_memory must start `align_offset` bytes into those 8 (or
            // at the end of them when align_offset == 0), not always 8
            // bytes past them. Reason (per Sig
            // `runtime/program/bpf/serialize.zig:171-172`):
            //
            //   region_start += BPF_ALIGN_OF_U128 -| align_offset
            //
            // For unaligned data (dlen%8 != 0): align_offset = 8 - dlen%8.
            // The first `align_offset` of the 8 zero bytes belong to the
            // NEXT region as leading alignment (it would have been written
            // by MODE 1/2's `appendNTimes(0, align_offset)` AFTER the data,
            // making the next account header 8-aligned). The remaining
            // `8 - align_offset` bytes are consumed by THIS account's data
            // section accounting.
            //
            // For aligned data (dlen%8 == 0): align_offset = 0. The full
            // 8 bytes are consumed by this account's data section, and
            // the next region starts at offset +8 (which is what the old
            // buggy code did — coincidentally correct for 8-aligned dlens).
            //
            // Pre-PR-5h3 the formula was `+ BPF_ALIGN_OF_U128` unconditionally,
            // which over-advanced host_curr by `align_offset` bytes for
            // every non-8-aligned account. Symptom: HJT-6009 (and any
            // program with non-8-aligned account data) panicked at
            // entrypoint.rs:353 with "index out of bounds: the len is 2
            // but the index is 198" because the BPF program read shifted
            // bytes that decoded as wrong field values.
            vaddr_curr = data_vaddr + data_reserved;
            host_curr = if (dm)
                layout.host_data_offset + (BPF_ALIGN_OF_U128 - alignPadForLen(dlen))
            else
                layout.host_data_offset + dlen + MAX_REALLOC;
        }

        // Trailing region: covers [host_curr .. total_size) in host space,
        // and starts at vaddr_curr in VM space.
        if (host_curr < total_size) {
            const tail_sz = total_size - host_curr;
            try input_regions.append(alloc, .{
                .vaddr_offset = vaddr_curr,
                .haddr = @ptrCast(&bytes[host_curr]),
                .region_sz = @intCast(tail_sz),
                .address_space_reserved = tail_sz,
                .is_writable = true,
                .acc_region_meta_idx = std.math.maxInt(u64),
            });
        }

        input_regions_out = try input_regions.toOwnedSlice(alloc);
        acc_metas_out = acc_metas;
    }

    return .{
        .bytes = bytes,
        .account_layouts = layouts,
        .instruction_data_offset = ix_off_host,
        .input_regions = input_regions_out,
        .acc_region_metas = acc_metas_out,
    };
}

// ── Public: deserialize (post-execute write-back) ─────────────────────────────

/// Walk the input buffer post-execution and read back each non-duplicate
/// account's lamports / data_len / data / owner into `accounts[i]`.
///
/// @prov:bpf.serialize-map — mirrors `deserialize_parameters_for_abiv1`,
/// flat-buffer path. Differences from upstream:
///
///  * Writes go through a `BorrowedInstructionAccount` with can-data-be-changed
///    checks upstream; here we simply populate `AccountOutput` and let the
///    caller (M8 invoke-context) decide whether the mutation is permitted.
///    This keeps the serializer pure: deserialization == reading.
///
///  * Duplicate slots are skipped — `accounts[i]` is left untouched. The
///    caller must derive duplicate values from the original-position entry,
///    same as upstream does via the dedup map.
///
/// The slices in `accounts[i].data` reference `input_buf` directly; they are
/// only valid for the lifetime of that buffer. Copy out before freeing the
/// input region.
pub fn deserializeReturn(
    input_buf: []const u8,
    accounts:  []AccountOutput,
    layouts:   []const SerializedAccount,
    direct_mapping: bool,
) SerializeError!void {
    if (accounts.len != layouts.len) return SerializeError.InvalidArgument;

    for (layouts, 0..) |layout, i| {
        if (layout.is_duplicate) continue;

        // 1) lamports
        if (layout.host_lamports_offset + 8 > input_buf.len) {
            return SerializeError.InvalidArgument;
        }
        const new_lamports = std.mem.readInt(
            u64,
            input_buf[layout.host_lamports_offset..][0..8],
            .little,
        );

        // 2) post data_len (the u64 immediately preceding the data offset)
        if (layout.host_data_offset < 8) return SerializeError.InvalidArgument;
        const dlen_off = layout.host_data_offset - 8;
        if (dlen_off + 8 > input_buf.len) return SerializeError.InvalidArgument;
        const post_len = std.mem.readInt(
            u64,
            input_buf[dlen_off..][0..8],
            .little,
        );

        // 3) post-len bounds. @prov:bpf.serialize-map
        const pre = layout.original_data_len;
        if (post_len > MAX_PERMITTED_DATA_LENGTH) return SerializeError.InvalidRealloc;
        if (post_len > pre + @as(u64, @intCast(MAX_PERMITTED_DATA_INCREASE))) {
            return SerializeError.InvalidRealloc;
        }
        const post_usize: usize = @intCast(post_len);

        // PR-5t (2026-05-19): MODE 3 (direct_mapping) — under direct mapping
        // the serializer wrote only an 8-byte BPF_ALIGN_OF_U128 zero pad at
        // the data position (per serialize.zig:463-477); the actual data
        // payload lives in `owned.tx.accounts[i].data` via the region's
        // haddr pointer, NOT in `input_buf`. So:
        //   • Skip the buffer-bounds check at host_data_offset+post_len
        //     (it would fail because input_buf is short of the data area).
        //   • Return an empty `data` slice as a placeholder — the caller
        //     (v2_dispatch.zig:1123-1127 / cpi.zig:1437-1465 post-PR-5s)
        //     already detects direct_mapping_active and pulls the canonical
        //     post-state from owned.tx.accounts[i].data instead of using
        //     `out.data`. Returning &[_]u8{} here is forward-safe — any
        //     caller that forgets the gate gets an empty slice (not garbage).
        //
        // Pre-PR-5t symptom (cluster-confirmed at testnet slot 409433065):
        // 1855 silent M5_DeserializeFailed errors for HJT-6009 transactions
        // (`HistoryJTGbKQD2mRgLZ3XhqHnN811Qpez8X9kCcGHoa`) per the PR-5p
        // BPF outcome instrumentation. HJT runs CopyGossipContactInfo /
        // CopyVoteAccount which has account data_len > 0 (e.g. 1024 bytes
        // for a vote account); the bounds check at line 722 fired because
        // `host_data_offset + 1024 > input_buf.len` (MODE 3 buffer has only
        // 8 bytes of pad after host_data_offset). Tx silently reverted on
        // Vexor; cluster ran it successfully → bank_hash diverged.
        const data: []const u8 = if (direct_mapping) blk: {
            break :blk &[_]u8{};
        } else blk: {
            if (layout.host_data_offset + post_usize > input_buf.len) {
                return SerializeError.InvalidArgument;
            }
            break :blk input_buf[layout.host_data_offset .. layout.host_data_offset + post_usize];
        };

        // 5) owner
        if (layout.host_owner_offset + 32 > input_buf.len) {
            return SerializeError.InvalidArgument;
        }
        var owner: [32]u8 = undefined;
        @memcpy(&owner, input_buf[layout.host_owner_offset..][0..32]);

        accounts[i] = .{
            .lamports = new_lamports,
            .owner    = owner,
            .data_len = post_usize,
            .data     = data,
        };
    }
}

// ── Compile-time invariants (sanity for downstream M8 wiring) ─────────────────

comptime {
    std.debug.assert(BPF_ALIGN_OF_U128 == 8); // vex-079
    std.debug.assert(MAX_REALLOC == 10 * 1024);
    std.debug.assert(NON_DUP_MARKER == 0xFF);
    std.debug.assert(INPUT_START == 0x4_0000_0000);
}
