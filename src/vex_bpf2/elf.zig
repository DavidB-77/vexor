//! Vexor sBPF ELF parser — spec-for-spec rebuild
//!
//! Canonical reference (locked):
//!   solana-sbpf v0.14.4 — solana-sbpf-v0.14.4/src/elf.rs
//!     plus solana-sbpf-v0.14.4/src/elf_parser/{mod,types,consts}.rs
//!   solana-sbpf v0.14.4 — src/program.rs (FunctionRegistry, SBPFVersion)
//!   solana-sbpf v0.14.4 — src/ebpf.rs   (MM_*, INSN_SIZE, hash_symbol_name)
//!   agave v4.0.0-beta.7 (SHA 65f2d111f0674d3a368fe80893f661c1099e1a5a) — pinned consumer.
//!
//! Zig idiom reference (non-authoritative): sig/src/vm/elf.zig
//!
//! This module is the M1 deliverable of the parallel-directory rebuild.
//! It is fully self-contained:
//!   - depends only on std
//!   - shares no types with src/vex_bpf/* (which is READ-ONLY for this rebuild)
//!   - other modules under src/vex_bpf2/ are owned by sister agents (M2/M5/M8)
//!
//! ── Mirrored agave-v4.0.0-beta.7 ranges ─────────────────────────────────────
//!   elf.rs:39-110     ElfError variants                  → LoadError below
//!   elf.rs:134-146    get_section helper                 → getSection()
//!   elf.rs:163-203    BPF relocation types               → BpfRelocationType
//!   elf.rs:217-253    Section + Executable struct        → Section / Executable
//!   elf.rs:336-373    new_from_text_bytes                → newFromTextBytes()
//!   elf.rs:376-403    load (dispatch by sbpf version)    → load()
//!   elf.rs:406-590    load_with_strict_parser (V3+)      → loadStrict()
//!   elf.rs:593-683    load_with_lenient_parser (V0-V2)   → loadLenient()
//!   elf.rs:713-775    validate                           → validate()
//!   elf.rs:778-901    parse_ro_sections                  → parseRoSections()
//!   elf.rs:904-1170   relocate                           → relocate()
//!   ebpf.rs:697-701   hash_symbol_name (Murmur3_32)      → hashSymbolName()
//!   ebpf.rs:36-51     MM_REGION_SIZE / MM_*              → mirrored constants below
//!
//! ── SIMD inventory (testnet activation status) ──────────────────────────────
//! All feature pubkeys harvested from solana-improvement-documents/
//! Testnet activation slot/epoch is gated by validator's FeatureSet, not this
//! parser. This parser HONORS the on/off semantics through the
//! `Config.enabled_sbpf_versions` bitset — flip versions in/out of the set as
//! features activate.
//!
//!   SIMD-0166  dynamic stack frames (V1)
//!     feature: JE86WkYvTrzW8HgNmrHY7dFYpCmSptUpKupbo2AdQ9cG
//!   SIMD-0173  sbpf instruction encoding improvements (V2)
//!     feature: F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP
//!   SIMD-0174  sbpf arithmetics improvements (V2 — same gate as 0173)
//!     feature: F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP
//!   SIMD-0178  static syscalls (V3)        — unified gate (see below)
//!   SIMD-0189  sbpf stricter ELF headers (V3) — unified gate (see below)
//!     feature: 5cC3foj77CWun58pC51ebHFUWavHWKarWyR5UUik7dnC
//!     (enable_sbpf_v3_deployment_and_execution; agave-v4.0.0-beta.7
//!      sdk/feature-set/src/lib.rs:1041-1042 + label :2125;
//!      not-yet active on testnet OR mainnet as of 2026-04 sweep
//!      → V3 path is mainnet-roadmap, not testnet-parity-critical today)
//!
//! Live testnet activation status NOT verified inline (Helius MCP defaults to
//! mainnet endpoints; testnet feature query is the runtime FeatureSet's job
//! per project_simd_0337/0340 pattern). This comment records the *contract*
//! between parser feature gates and on-chain activations; runtime caller MUST
//! pass `Config.enabled_sbpf_versions` derived from the live FeatureSet.
//!
//! ── fix ledger invariants honored ───────────────────────────────────────────
//! These come from this project's internal fix-tracking ledger (locked,
//! previously-fixed-bug invariants that must not regress).
//! Note on tag naming: the spec for this task references `vex-152n` /
//! `vex-152o` as locked invariants. As of the worktree's fix_ledger snapshot,
//! those exact tags are NOT present as named entries — but their *semantics*
//! ARE locked by upstream agave parity:
//!
//!   vex-152n (program_region_vaddr = text_vaddr + base_vaddr)
//!     → For V0-V2 (lenient) programs the linker-assigned base is folded into
//!       text_vaddr (elf.rs:615 — `text_section_vaddr = sh_addr + MM_REGION_SIZE`).
//!     → For V3+ (strict) programs the bytecode header's p_vaddr IS
//!       MM_BYTECODE_START outright, so base_vaddr=0 and the formula reduces
//!       to text_vaddr.
//!     → We expose a single `programRegionVaddr()` accessor that returns the
//!       VM-facing address of byte 0 of .text in both regimes. Internally we
//!       store text_vaddr as the *combined* value; base_vaddr=0 is canonical
//!       on the strict path.
//!
//!   vex-152o (single .text enforcement)
//!     → elf.rs:731-744 — counts sections named `.text` and rejects with
//!       NotOneTextSection unless count == 1. Mirrored verbatim in validate().
//!
//!   vex-079 (BPF_ALIGN_OF_U128 = 8)
//!     → This is a serializer invariant (sbpf_executor.zig per-account
//!       align_pad), NOT an ELF parser invariant. The parser does NOT depend
//!       on it. Recorded here so a future reader doesn't accidentally weave
//!       16-byte alignment into the ELF parsing path.

const std = @import("std");

// ─── Public API constants ─────────────────────────────────────────────────────

/// sBPF ABI version. Mirrors solana-sbpf-0.14.4 program.rs:13-26 SBPFVersion.
pub const SbpfVersion = enum(u8) {
    v0 = 0, // legacy rbpf
    v1 = 1, // SIMD-0166 dynamic stack frames
    v2 = 2, // SIMD-0173/0174 encoding + arithmetic
    v3 = 3, // SIMD-0178 static syscalls + SIMD-0189 stricter ELF

    /// Strict program-header-driven parser (V3+). elf.rs:396.
    pub fn enableStricterElfHeaders(self: SbpfVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(SbpfVersion.v3);
    }

    /// Static syscall (no symbol-name hashing on call_imm). elf.rs uses for
    /// register_function_hashed_legacy "skip-hash" branch. program.rs:75-77.
    pub fn staticSyscalls(self: SbpfVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(SbpfVersion.v3);
    }

    /// V3+ rodata starts at MM_RODATA_START (=0); V0-V2 rodata is offset +
    /// MM_REGION_SIZE. program.rs:83-85.
    pub fn enableLowerRodataVaddr(self: SbpfVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(SbpfVersion.v3);
    }
};

/// Configuration affecting how strictly the loader rejects malformed ELFs.
/// Mirrors a subset of solana-sbpf vm.rs:Config; only fields the ELF loader
/// actually consults are present.
pub const Config = struct {
    /// Bitmask: which SBPFVersions the runtime currently allows.
    /// bit i set ⇒ Vi accepted. Default = V0..V3 enabled.
    enabled_sbpf_versions: u8 = 0b1111,

    /// Reject ELFs with offset/addr inconsistencies. elf.rs:616, 823, 839.
    reject_broken_elfs: bool = false,

    /// Group readonly sections at MM_REGION_SIZE+offset (V1+ default true).
    optimize_rodata: bool = true,

    /// Track section/symbol names (extra parsing work). elf.rs:518, 931, 1150.
    enable_symbol_and_section_labels: bool = false,

    /// Carrier #9 fix (2026-06-10, @414537973): the LOADER's registered-syscall
    /// key set (murmur3 name hashes), used by relocate() for non-function
    /// R_BPF_64_32 symbols — Agave elf.rs:1129-1136 looks the hash up in
    /// `loader.get_function_registry(sbpf_version)` and rejects (UnknownSymbol,
    /// reject_broken_elfs only) ONLY when the import is not a registered
    /// syscall. The previous code consulted the ELF's OWN function registry
    /// here, which never contains syscalls — so every real-world program
    /// (they all import at least sol_log_) was rejected at deploy/upgrade/
    /// extend verification. null = no loader set available; relocation then
    /// skips the membership check (pre-fix behavior minus the false reject).
    loader_syscall_keys: ?[]const u32 = null,

    pub const DEFAULT: Config = .{};

    pub fn versionEnabled(self: Config, v: SbpfVersion) bool {
        const shift: u3 = @intCast(@intFromEnum(v));
        const bit: u8 = @as(u8, 1) << shift;
        return (self.enabled_sbpf_versions & bit) != 0;
    }
};

/// All loader-side errors. Each maps to an ElfError variant in elf.rs:39-110.
pub const LoadError = error{
    /// File too short to contain ELF64 file header (elf.rs:418, 446).
    OutOfBounds,
    /// e_ident.ei_class != ELFCLASS64. elf.rs:715-717 / 444.
    WrongClass,
    /// e_ident.ei_data != ELFDATA2LSB. elf.rs:718-720 / 444.
    WrongEndianess,
    /// e_ident.ei_osabi != ELFOSABI_NONE (or pad nonzero in strict). elf.rs:721-723.
    WrongAbi,
    /// e_machine ∉ {EM_BPF=247, EM_SBPF=263}. elf.rs:724-726.
    WrongMachine,
    /// e_type != ET_DYN. elf.rs:727-729.
    WrongType,
    /// Multiple or zero `.text` sections. elf.rs:742-744 (vex-152o).
    NotOneTextSection,
    /// Writable `.bss` / `.data` (non-`.data.rel`). elf.rs:746-757.
    WritableSectionNotSupported,
    /// Section header table has invalid offset/size. elf.rs:759-768.
    InvalidSectionHeader,
    /// Strict path: program-header constraints failed. elf.rs:445, 481.
    InvalidProgramHeader,
    /// e_flags / general file-header sanity violation. elf.rs:445, 508.
    InvalidFileHeader,
    /// .text not found by name. elf.rs:614, 769.
    SectionNotFound,
    /// Entry point outside .text vm range. elf.rs:771, 506-509.
    EntrypointOutOfBounds,
    /// Entry offset not multiple of 8 / divides badly. elf.rs:633, 506.
    InvalidEntrypoint,
    /// Branch target outside .text. elf.rs:929.
    RelativeJumpOutOfBounds,
    /// Two distinct symbols hash to the same key. program.rs:131-135.
    SymbolHashCollision,
    /// Relocation references a symbol index that does not exist. elf.rs:969.
    UnknownSymbol,
    /// Relocation references unknown / unsupported relocation type. elf.rs:1146.
    UnknownRelocation,
    /// Relocation post-condition zero/wrong vaddr. elf.rs:1049.
    InvalidVirtualAddress,
    /// Generic offset/length out-of-range during parse. elf.rs:103.
    ValueOutOfBounds,
    /// e_flags encodes a version not enabled by Config. elf.rs:392-394.
    UnsupportedSbpfVersion,
    /// File exceeds the parser's hard cap (sanity guard, not in agave).
    ProgramTooLarge,
    /// Allocator returned null.
    OutOfMemory,
};

// ─── ebpf::* mirrored constants (elf.rs imports these) ────────────────────────

/// elf.rs uses ebpf::INSN_SIZE = 8.
const INSN_SIZE: u64 = 8;
/// elf.rs uses ebpf::HOST_ALIGN = 16. ELF buffer alignment for direct casts.
const HOST_ALIGN: usize = 16;
/// ebpf.rs:38. Used to derive vaddr regions and rodata-index check.
const VIRTUAL_ADDRESS_BITS: u6 = 32;
/// ebpf.rs:41. 1<<32 = 4 GiB per vm region.
const MM_REGION_SIZE: u64 = 1 << VIRTUAL_ADDRESS_BITS;
/// ebpf.rs:43.
const MM_RODATA_START: u64 = 0;
/// ebpf.rs:45.
const MM_BYTECODE_START: u64 = MM_REGION_SIZE;
/// ebpf.rs:47.
const MM_STACK_START: u64 = MM_REGION_SIZE * 2;

/// Hard cap. Solana on-chain BPF programs are bounded; matches vex_bpf MAX_FILE_SIZE.
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

// ─── ELF64 wire types (elf_parser/types.rs) ───────────────────────────────────

const ELFMAG: [4]u8 = .{ 0x7F, 0x45, 0x4C, 0x46 };
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const EV_CURRENT: u32 = 1;

const EM_BPF: u16 = 247;
const EM_SBPF: u16 = 263;
const ET_DYN: u16 = 3;

const PT_LOAD: u32 = 1;

const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

const SHN_UNDEF: u16 = 0;
const STT_FUNC: u8 = 2;

// BPF relocation types (elf.rs:163-203).
const R_BPF_NONE: u32 = 0;
const R_BPF_64_64: u32 = 1;
const R_BPF_64_RELATIVE: u32 = 8;
const R_BPF_64_32: u32 = 10;

/// elf.rs:164-166.
const BYTE_OFFSET_IMMEDIATE: usize = 4;
const BYTE_LENGTH_IMMEDIATE: usize = 4;

const ElfIdent = extern struct {
    ei_mag: [4]u8,
    ei_class: u8,
    ei_data: u8,
    ei_version: u8,
    ei_osabi: u8,
    ei_abiversion: u8,
    ei_pad: [7]u8,
};

const Elf64Ehdr = extern struct {
    e_ident: ElfIdent,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const Elf64Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

const Elf64Rel = extern struct {
    r_offset: u64,
    r_info: u64,

    pub fn rType(self: Elf64Rel) u32 {
        return @truncate(self.r_info & 0xffff_ffff);
    }
    pub fn rSym(self: Elf64Rel) u32 {
        return @truncate(self.r_info >> 32);
    }
};

// ─── Function registry (lightweight; mirrors program.rs:120-178 minus the
// ─── Cow / generic context bits) ──────────────────────────────────────────────

pub const FunctionRegistry = struct {
    /// hash → pc
    map: std.AutoHashMapUnmanaged(u32, usize) = .{},

    pub fn deinit(self: *FunctionRegistry, alloc: std.mem.Allocator) void {
        self.map.deinit(alloc);
    }

    /// Insert (key, pc). Hash-collision on differing pc returns
    /// SymbolHashCollision (mirrors program.rs:131-135).
    pub fn registerKey(
        self: *FunctionRegistry,
        alloc: std.mem.Allocator,
        key: u32,
        pc: usize,
    ) LoadError!void {
        const gop = self.map.getOrPut(alloc, key) catch return LoadError.OutOfMemory;
        if (gop.found_existing) {
            if (gop.value_ptr.* != pc) return LoadError.SymbolHashCollision;
            return;
        }
        gop.value_ptr.* = pc;
    }

    /// Hashed-legacy registration: pre-V3 hashes bytes-of-pc (or "entrypoint"),
    /// V3+ uses the pc directly as the key. program.rs:142-177.
    pub fn registerHashedLegacy(
        self: *FunctionRegistry,
        alloc: std.mem.Allocator,
        version: SbpfVersion,
        name: []const u8,
        pc: usize,
    ) LoadError!u32 {
        const key: u32 = blk: {
            if (!version.staticSyscalls()) {
                if (std.mem.eql(u8, name, "entrypoint")) {
                    break :blk hashSymbolName("entrypoint");
                }
                var buf: [@sizeOf(usize)]u8 = undefined;
                std.mem.writeInt(usize, &buf, pc, .little);
                break :blk hashSymbolName(&buf);
            } else {
                break :blk @truncate(pc);
            }
        };
        try self.registerKey(alloc, key, pc);
        return key;
    }

    pub fn lookupByKey(self: *const FunctionRegistry, key: u32) ?usize {
        return self.map.get(key);
    }

    pub fn unregister(self: *FunctionRegistry, key: u32) void {
        _ = self.map.remove(key);
    }
};

/// Murmur3_32 over a byte slice with seed=0. Mirrors ebpf.rs:697-701.
pub fn hashSymbolName(name: []const u8) u32 {
    return std.hash.Murmur3_32.hashWithSeed(name, 0);
}

// ─── Section storage discriminator (elf.rs:217-230) ───────────────────────────

pub const Section = union(enum) {
    /// (vaddr_offset, owned bytes). elf.rs:223.
    owned: struct { offset: usize, data: []u8 },
    /// (vaddr_offset, [start, end) into elf_bytes). elf.rs:229.
    borrowed: struct { offset: usize, start: usize, end: usize },
};

// ─── Public Executable ────────────────────────────────────────────────────────

pub const Executable = struct {
    /// Owned, HOST_ALIGN-aligned ELF buffer (relocations are written in-place
    /// for V0-V2). elf.rs:236.
    elf_bytes: []align(HOST_ALIGN) u8,
    /// Detected sbpf version (set in load() — not by sub-parsers). elf.rs:401.
    sbpf_version: SbpfVersion,
    /// Read-only data (.text + .rodata + .data.rel.ro + .eh_frame, merged).
    /// elf.rs:240, 497, 649.
    ro_section: Section,
    /// VM-facing virtual address of byte 0 of .text. elf.rs:242.
    /// vex-152n: this is the *combined* value (text_vaddr + base_vaddr) —
    /// see module-level comment.
    text_section_vaddr: u64,
    /// [start, end) into elf_bytes. elf.rs:244.
    text_start: usize,
    text_end: usize,
    /// Entry instruction index into .text. elf.rs:246.
    entry_pc: usize,
    /// hash → pc. elf.rs:248.
    function_registry: FunctionRegistry,
    /// Tracks which allocator owns elf_bytes / ro_section / function_registry.
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Executable) void {
        self.allocator.free(self.elf_bytes);
        switch (self.ro_section) {
            .owned => |o| self.allocator.free(o.data),
            .borrowed => {},
        }
        self.function_registry.deinit(self.allocator);
    }

    pub fn textBytes(self: *const Executable) []const u8 {
        return self.elf_bytes[self.text_start..self.text_end];
    }
    pub fn textVaddr(self: *const Executable) u64 {
        return self.text_section_vaddr;
    }
    /// vex-152n: program region vaddr = text_vaddr + base_vaddr.
    /// Because we fold base into text_section_vaddr at load time, the public
    /// accessor is just the stored field. Kept as a separate function so call
    /// sites stay self-documenting.
    pub fn programRegionVaddr(self: *const Executable) u64 {
        return self.text_section_vaddr;
    }
    pub fn entryPoint(self: *const Executable) u64 {
        return @intCast(self.entry_pc);
    }
    pub fn version(self: *const Executable) SbpfVersion {
        return self.sbpf_version;
    }
    pub fn rodata(self: *const Executable) []const u8 {
        return switch (self.ro_section) {
            .owned => |o| o.data,
            .borrowed => |b| self.elf_bytes[b.start..b.end],
        };
    }

    /// VM address where the read-only region (.text + .rodata + .data.rel.ro,
    /// merged) is mapped.
    /// - V0/V1/V2 lenient: this equals MM_REGION_SIZE + lowest_sh_addr; for
    ///   typical Anchor ELFs that's 0x100000120 (with .text sh_addr=0x120).
    /// - V3 strict: equals MM_RODATA_START (=0) for separate-rodata layout.
    /// Caller (v2_dispatch.zig) MUST use this — NOT the hardcoded
    /// MM_RODATA_START — to construct the rodata MemoryRegion. Otherwise
    /// vmap shifts by `lowest_sh_addr` bytes (Forge SEQ:72 finding).
    pub fn rodataVaddr(self: *const Executable) u64 {
        return switch (self.ro_section) {
            .owned => |o| @intCast(o.offset),
            .borrowed => |b| @intCast(b.offset),
        };
    }

    pub fn load(
        alloc: std.mem.Allocator,
        bytes: []const u8,
        cfg: Config,
    ) LoadError!Executable {
        return loadInner(alloc, bytes, cfg);
    }
};

// ─── load (dispatch) — elf.rs:376-403 ─────────────────────────────────────────

fn loadInner(
    alloc: std.mem.Allocator,
    bytes: []const u8,
    cfg: Config,
) LoadError!Executable {
    if (bytes.len < @sizeOf(Elf64Ehdr)) return LoadError.OutOfBounds;
    if (bytes.len > MAX_FILE_SIZE) return LoadError.ProgramTooLarge;

    // Read e_flags directly to determine version BEFORE deeper parsing.
    // elf.rs:377-391.
    const E_FLAGS_OFFSET: usize = 48;
    if (bytes.len < E_FLAGS_OFFSET + 4) return LoadError.OutOfBounds;
    const e_flags_le = std.mem.readInt(u32, bytes[E_FLAGS_OFFSET..][0..4], .little);
    const v: SbpfVersion = switch (e_flags_le) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => return LoadError.UnsupportedSbpfVersion,
    };
    if (!cfg.versionEnabled(v)) return LoadError.UnsupportedSbpfVersion;

    // Aligned copy of input bytes (elf.rs:415, 598-605).
    const aligned = alloc.alignedAlloc(u8, .of(u128), bytes.len) catch
        return LoadError.OutOfMemory;
    // u128 align (16) == HOST_ALIGN. Cast through to declared alignment.
    const aligned16: []align(HOST_ALIGN) u8 = @alignCast(aligned);
    errdefer alloc.free(aligned16);
    @memcpy(aligned16, bytes);

    var exe = if (v.enableStricterElfHeaders())
        try loadStrict(alloc, aligned16, cfg)
    else
        try loadLenient(alloc, aligned16, cfg);
    exe.sbpf_version = v;
    return exe;
}

// ─── loadStrict — elf.rs:406-590 (V3+ program-header-only parser) ─────────────

fn loadStrict(
    alloc: std.mem.Allocator,
    elf_bytes: []align(HOST_ALIGN) u8,
    cfg: Config,
) LoadError!Executable {
    _ = cfg; // strict path ignores most config knobs (it IS the strict knob).

    if (elf_bytes.len < @sizeOf(Elf64Ehdr)) return LoadError.OutOfBounds;
    const hdr: *const Elf64Ehdr =
        @ptrCast(@alignCast(elf_bytes.ptr));

    const ph_table_start: usize = @sizeOf(Elf64Ehdr);
    const ph_count: usize = hdr.e_phnum;
    const ph_bytes = std.math.mul(usize, ph_count, @sizeOf(Elf64Phdr)) catch
        return LoadError.ValueOutOfBounds;
    const ph_table_end: usize = ph_table_start + ph_bytes;

    // elf.rs:423-446 — file-header invariants.
    if (!std.mem.eql(u8, hdr.e_ident.ei_mag[0..], ELFMAG[0..]) or
        hdr.e_ident.ei_class != ELFCLASS64 or
        hdr.e_ident.ei_data != ELFDATA2LSB or
        hdr.e_ident.ei_version != @as(u8, @intCast(EV_CURRENT)) or
        hdr.e_ident.ei_osabi != ELFOSABI_NONE or
        hdr.e_ident.ei_abiversion != 0 or
        !std.mem.allEqual(u8, hdr.e_ident.ei_pad[0..], 0) or
        hdr.e_machine != EM_BPF or
        hdr.e_version != EV_CURRENT or
        hdr.e_phoff != @sizeOf(Elf64Ehdr) or
        hdr.e_ehsize != @sizeOf(Elf64Ehdr) or
        hdr.e_phentsize != @sizeOf(Elf64Phdr) or
        hdr.e_phnum == 0 or
        ph_table_end > elf_bytes.len)
    {
        return LoadError.InvalidFileHeader;
    }

    // elf.rs:448-451 — expected program header layout.
    const Expected = struct { flags: u32, vaddr: u64 };
    const expected = [_]Expected{
        .{ .flags = PF_R, .vaddr = MM_RODATA_START },
        .{ .flags = PF_X, .vaddr = MM_BYTECODE_START },
    };

    // Peek phdr[0] to decide if rodata header is present (elf.rs:454-463).
    const ph_table_bytes = elf_bytes[ph_table_start..ph_table_end];
    const phdrs = std.mem.bytesAsSlice(Elf64Phdr, ph_table_bytes);
    const skip_rodata = phdrs[0].p_flags != expected[0].flags;
    const exp_start: usize = if (skip_rodata) 1 else 0;
    if (!skip_rodata and hdr.e_phnum < 2) return LoadError.InvalidFileHeader;

    var expected_offset: u64 = @intCast(ph_table_end);
    var i: usize = 0;
    const exp_count: usize = expected.len - exp_start;
    while (i < exp_count) : (i += 1) {
        const ph = phdrs[i];
        const e = expected[exp_start + i];
        if (ph.p_type != PT_LOAD or
            ph.p_flags != e.flags or
            ph.p_offset != expected_offset or
            ph.p_offset >= @as(u64, elf_bytes.len) or
            (ph.p_offset % INSN_SIZE) != 0 or
            ph.p_vaddr != e.vaddr or
            ph.p_paddr != e.vaddr or
            ph.p_filesz != ph.p_memsz or
            ph.p_filesz > @as(u64, elf_bytes.len) -| ph.p_offset or
            (ph.p_filesz % INSN_SIZE) != 0 or
            ph.p_memsz >= MM_REGION_SIZE)
        {
            return LoadError.InvalidProgramHeader;
        }
        expected_offset = expected_offset +| ph.p_filesz;
    }

    // Resolve bytecode header (elf.rs:486-498).
    var ro_start: usize = ph_table_end;
    var ro_end: usize = ph_table_end;
    var bytecode_phdr: Elf64Phdr = undefined;
    if (skip_rodata) {
        bytecode_phdr = phdrs[0];
    } else {
        const ro = phdrs[0];
        ro_start = @intCast(ro.p_offset);
        ro_end = @intCast(ro.p_offset +| ro.p_filesz);
        bytecode_phdr = phdrs[1];
    }

    const text_vaddr = bytecode_phdr.p_vaddr;
    const text_start: usize = @intCast(bytecode_phdr.p_offset);
    const text_end: usize = @intCast(bytecode_phdr.p_offset +| bytecode_phdr.p_filesz);

    // Entry-point check (elf.rs:501-509).
    const vm_lo = bytecode_phdr.p_vaddr;
    const vm_hi = bytecode_phdr.p_vaddr +| bytecode_phdr.p_memsz;
    const probe = hdr.e_entry +| INSN_SIZE -| 1;
    if (!(vm_lo <= probe and probe < vm_hi) or
        (hdr.e_entry % INSN_SIZE) != 0)
    {
        return LoadError.InvalidFileHeader;
    }
    const entry_byte = hdr.e_entry -| bytecode_phdr.p_vaddr;
    const entry_pc: usize = @intCast(entry_byte / INSN_SIZE);

    var registry = FunctionRegistry{};
    errdefer registry.deinit(alloc);

    return Executable{
        .elf_bytes = elf_bytes,
        .sbpf_version = .v3, // overwritten by caller
        .ro_section = .{ .borrowed = .{
            .offset = @intCast(MM_RODATA_START),
            .start = ro_start,
            .end = ro_end,
        } },
        .text_section_vaddr = text_vaddr,
        .text_start = text_start,
        .text_end = text_end,
        .entry_pc = entry_pc,
        .function_registry = registry,
        .allocator = alloc,
    };
}

// ─── loadLenient — elf.rs:593-683 (V0-V2 path with relocations) ───────────────

fn loadLenient(
    alloc: std.mem.Allocator,
    elf_bytes: []align(HOST_ALIGN) u8,
    cfg: Config,
) LoadError!Executable {
    if (elf_bytes.len < @sizeOf(Elf64Ehdr)) return LoadError.OutOfBounds;
    const hdr: *const Elf64Ehdr = @ptrCast(@alignCast(elf_bytes.ptr));

    try validate(hdr, elf_bytes);

    const text_sh = (try findSectionByName(hdr, elf_bytes, ".text")) orelse
        return LoadError.SectionNotFound;
    const text_vaddr = text_sh.sh_addr +| MM_REGION_SIZE;
    if ((cfg.reject_broken_elfs and text_sh.sh_addr != text_sh.sh_offset) or
        text_vaddr > MM_STACK_START)
    {
        return LoadError.ValueOutOfBounds;
    }

    var registry = FunctionRegistry{};
    errdefer registry.deinit(alloc);
    try relocate(&registry, alloc, hdr, elf_bytes, cfg, text_sh);

    // Entry pc (elf.rs:632-647).
    const entry_off = hdr.e_entry -| text_sh.sh_addr;
    if ((entry_off % INSN_SIZE) != 0) return LoadError.InvalidEntrypoint;
    const entry_pc: usize = @intCast(entry_off / INSN_SIZE);
    // Re-register entrypoint at correct pc (elf.rs:637-643).
    registry.unregister(hashSymbolName("entrypoint"));
    _ = try registry.registerHashedLegacy(alloc, .v0, "entrypoint", entry_pc);

    const ro = try parseRoSections(alloc, hdr, elf_bytes, cfg);
    const ro_vaddr_offset: u64 = switch (ro) {
        .owned => |o| @intCast(o.offset),
        .borrowed => |b| @intCast(b.offset),
    };
    if (cfg.optimize_rodata) {
        const idx = ro_vaddr_offset >> VIRTUAL_ADDRESS_BITS;
        if (idx != 1) {
            // Free ro before bubbling.
            switch (ro) {
                .owned => |o| alloc.free(o.data),
                .borrowed => {},
            }
            return LoadError.ValueOutOfBounds;
        }
    }

    const text_start: usize = @intCast(text_sh.sh_offset);
    const text_end_u64 = text_sh.sh_offset +| text_sh.sh_size;
    if (text_end_u64 > @as(u64, elf_bytes.len)) {
        switch (ro) {
            .owned => |o| alloc.free(o.data),
            .borrowed => {},
        }
        return LoadError.ValueOutOfBounds;
    }

    return Executable{
        .elf_bytes = elf_bytes,
        .sbpf_version = .v0, // overwritten by caller
        .ro_section = ro,
        .text_section_vaddr = text_vaddr,
        .text_start = text_start,
        .text_end = @intCast(text_end_u64),
        .entry_pc = entry_pc,
        .function_registry = registry,
        .allocator = alloc,
    };
}

// ─── validate — elf.rs:713-775 ────────────────────────────────────────────────

fn validate(hdr: *const Elf64Ehdr, elf_bytes: []const u8) LoadError!void {
    if (hdr.e_ident.ei_class != ELFCLASS64) return LoadError.WrongClass;
    if (hdr.e_ident.ei_data != ELFDATA2LSB) return LoadError.WrongEndianess;
    if (hdr.e_ident.ei_osabi != ELFOSABI_NONE) return LoadError.WrongAbi;
    if (hdr.e_machine != EM_BPF and hdr.e_machine != EM_SBPF)
        return LoadError.WrongMachine;
    if (hdr.e_type != ET_DYN) return LoadError.WrongType;

    // vex-152o: count `.text` sections and require exactly one.
    var num_text: usize = 0;
    var it = sectionIterator(hdr, elf_bytes);
    while (try it.next()) |entry| {
        if (entry.name) |n| if (std.mem.eql(u8, n, ".text")) {
            num_text += 1;
        };
    }
    if (num_text != 1) return LoadError.NotOneTextSection;

    // Forbid writable .bss / .data (elf.rs:746-757).
    var it2 = sectionIterator(hdr, elf_bytes);
    while (try it2.next()) |entry| {
        if (entry.name) |n| {
            const writable = (entry.shdr.sh_flags & SHF_WRITE) != 0;
            if (std.mem.startsWith(u8, n, ".bss") or
                (writable and std.mem.startsWith(u8, n, ".data") and
                    !std.mem.startsWith(u8, n, ".data.rel")))
            {
                return LoadError.WritableSectionNotSupported;
            }
        }
    }

    // Section file ranges must be in-bounds (elf.rs:759-768).
    var it3 = sectionIterator(hdr, elf_bytes);
    while (try it3.next()) |entry| {
        const start = entry.shdr.sh_offset;
        const end = std.math.add(u64, entry.shdr.sh_offset, entry.shdr.sh_size) catch
            return LoadError.ValueOutOfBounds;
        if (entry.shdr.sh_type == SHT_NOBITS) continue; // not in file
        if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
        _ = start;
    }

    // Entrypoint within .text vm range (elf.rs:769-772).
    const text_sh = (try findSectionByName(hdr, elf_bytes, ".text")) orelse
        return LoadError.SectionNotFound;
    if (!(text_sh.sh_addr <= hdr.e_entry and
        hdr.e_entry < text_sh.sh_addr +| text_sh.sh_size))
    {
        return LoadError.EntrypointOutOfBounds;
    }
}

// ─── parseRoSections — elf.rs:778-901 ─────────────────────────────────────────

fn parseRoSections(
    alloc: std.mem.Allocator,
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
    cfg: Config,
) LoadError!Section {
    var lowest: usize = std.math.maxInt(usize);
    var highest: usize = 0;
    var fill: usize = 0;
    var first_idx: usize = 0;
    var last_idx: usize = 0;
    var n_ro: usize = 0;
    var invalid_offsets = false;

    // Bounded scratch for slices (16 readable sections is plenty for sBPF).
    var slices_buf: [32]struct { addr: usize, range_start: usize, range_end: usize } = undefined;
    var slices_len: usize = 0;

    var it = sectionIterator(hdr, elf_bytes);
    var idx: usize = 0;
    while (try it.next()) |entry| : (idx += 1) {
        const name = entry.name orelse continue;
        const is_ro = std.mem.eql(u8, name, ".text") or
            std.mem.eql(u8, name, ".rodata") or
            std.mem.eql(u8, name, ".data.rel.ro") or
            std.mem.eql(u8, name, ".eh_frame");
        if (!is_ro) continue;

        if (n_ro == 0) first_idx = idx;
        last_idx = idx;
        n_ro += 1;

        const addr = entry.shdr.sh_addr;
        if (!invalid_offsets and addr != entry.shdr.sh_offset) invalid_offsets = true;

        const vaddr_end = addr +| MM_REGION_SIZE;
        if ((cfg.reject_broken_elfs and invalid_offsets) or vaddr_end > MM_STACK_START)
            return LoadError.ValueOutOfBounds;

        const off = entry.shdr.sh_offset;
        const len = entry.shdr.sh_size;
        if (entry.shdr.sh_type == SHT_NOBITS) continue;
        const end = std.math.add(u64, off, len) catch return LoadError.ValueOutOfBounds;
        if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;

        if (slices_len >= slices_buf.len) return LoadError.ValueOutOfBounds;
        slices_buf[slices_len] = .{
            .addr = @intCast(addr),
            .range_start = @intCast(off),
            .range_end = @intCast(end),
        };
        slices_len += 1;

        const addr_us: usize = @intCast(addr);
        if (addr_us < lowest) lowest = addr_us;
        if (addr_us + @as(usize, @intCast(len)) > highest)
            highest = addr_us + @as(usize, @intCast(len));
        fill += @intCast(len);
    }

    if (cfg.reject_broken_elfs and lowest +| fill > highest)
        return LoadError.ValueOutOfBounds;

    const can_borrow = !invalid_offsets and
        ((last_idx + 1) -| first_idx) == n_ro;

    if (cfg.optimize_rodata and can_borrow and n_ro > 0) {
        const addr_offset: usize = if (lowest >= @as(usize, @intCast(MM_REGION_SIZE)))
            lowest
        else
            lowest +| @as(usize, @intCast(MM_REGION_SIZE));
        return Section{ .borrowed = .{
            .offset = addr_offset,
            .start = lowest,
            .end = highest,
        } };
    }

    var hi = highest;
    var lo = lowest;
    if (cfg.optimize_rodata) {
        hi = hi -| lo;
    } else {
        lo = 0;
    }
    if (hi > elf_bytes.len) return LoadError.ValueOutOfBounds;
    if (n_ro == 0 or hi == 0) {
        // Empty ro region. Match Section::Owned with empty data, offset 0.
        const buf = alloc.alloc(u8, 0) catch return LoadError.OutOfMemory;
        return Section{ .owned = .{ .offset = @intCast(MM_REGION_SIZE), .data = buf } };
    }
    const buf = alloc.alloc(u8, hi) catch return LoadError.OutOfMemory;
    @memset(buf, 0);
    var i: usize = 0;
    while (i < slices_len) : (i += 1) {
        const s = slices_buf[i];
        const dst_off = s.addr -| lo;
        const slen = s.range_end - s.range_start;
        if (dst_off + slen > buf.len) {
            alloc.free(buf);
            return LoadError.ValueOutOfBounds;
        }
        @memcpy(buf[dst_off .. dst_off + slen], elf_bytes[s.range_start..s.range_end]);
    }
    const addr_offset: usize = if (lowest >= @as(usize, @intCast(MM_REGION_SIZE)))
        lowest
    else
        lowest +| @as(usize, @intCast(MM_REGION_SIZE));
    return Section{ .owned = .{ .offset = addr_offset, .data = buf } };
}

// ─── relocate — elf.rs:904-1170 ───────────────────────────────────────────────
//
// In-place relocation of the ELF file. Handles three relocation types:
//   R_BPF_64_64       : ld_imm64 → split low/high 32 bits across two slots
//   R_BPF_64_RELATIVE : in-text lddw fixup; out-of-text 64-bit fixup
//   R_BPF_64_32       : call → murmur-3 hash of symbol name (legacy hash)
//
// Symbol-and-section labels (elf.rs:1150-1167) are skipped when the config
// flag is off (default false). Without the flag, the registry only carries:
//   - legacy-hashed CALL_IMM-relative target keys (registered during the
//     local-call fixup loop)
//   - the entrypoint key (registered by the caller after relocate returns)
//   - dynamic-symbol R_BPF_64_32 keys
//
// Dynamic relocation discovery is best-effort: if the .dynamic section / RELA
// table is absent or malformed, we treat it as "no relocations" rather than
// erroring (mirrors agave's `dynamic_relocations_table().unwrap_or_default()`).

const CALL_IMM_OPCODE: u8 = 0x85;

fn relocate(
    registry: *FunctionRegistry,
    alloc: std.mem.Allocator,
    hdr: *const Elf64Ehdr,
    elf_bytes: []u8,
    cfg: Config,
    text_sh: Elf64Shdr,
) LoadError!void {
    const text_start_u64 = text_sh.sh_offset;
    const text_end_u64 = text_sh.sh_offset +| text_sh.sh_size;
    if (text_end_u64 > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
    const text_start: usize = @intCast(text_start_u64);
    const text_end: usize = @intCast(text_end_u64);
    const text_bytes = elf_bytes[text_start..text_end];
    if ((text_bytes.len % @as(usize, @intCast(INSN_SIZE))) != 0)
        return LoadError.ValueOutOfBounds;
    const insn_count = text_bytes.len / @as(usize, @intCast(INSN_SIZE));

    // (1) PC-relative CALL_IMM fixups (elf.rs:917-948).
    var i: usize = 0;
    while (i < insn_count) : (i += 1) {
        const off = i * @as(usize, @intCast(INSN_SIZE));
        const opc = text_bytes[off];
        if (opc != CALL_IMM_OPCODE) continue;
        const imm = std.mem.readInt(i32, text_bytes[off + 4 ..][0..4], .little);
        if (imm == -1) continue;
        const target_pc_signed: i64 = @as(i64, @intCast(i)) +| 1 +| @as(i64, imm);
        if (target_pc_signed < 0 or target_pc_signed >= @as(i64, @intCast(insn_count)))
            return LoadError.RelativeJumpOutOfBounds;
        const target_pc: usize = @intCast(target_pc_signed);
        const key = try registry.registerHashedLegacy(alloc, .v0, "", target_pc);
        std.mem.writeInt(u32, text_bytes[off + 4 ..][0..4], key, .little);
    }

    // (2) Dynamic relocations (elf.rs:951-1148). Best-effort discovery.
    const relas = try findDynamicRelas(hdr, elf_bytes);
    const dynsym = try findDynsym(hdr, elf_bytes);
    const dynstr = try findDynstr(hdr, elf_bytes);

    for (relas) |rel| {
        const r_off: usize = @intCast(rel.r_offset);
        const rtype = rel.rType();

        switch (rtype) {
            R_BPF_NONE => {},

            R_BPF_64_64 => {
                const imm_off = r_off +| BYTE_OFFSET_IMMEDIATE;
                if (imm_off + BYTE_LENGTH_IMMEDIATE > elf_bytes.len)
                    return LoadError.ValueOutOfBounds;
                const refd = std.mem.readInt(u32, elf_bytes[imm_off..][0..4], .little);
                const sym_idx = rel.rSym();
                if (sym_idx >= dynsym.len) return LoadError.UnknownSymbol;
                const sym = dynsym[sym_idx];
                var addr: u64 = sym.st_value +| @as(u64, refd);
                if (addr < MM_REGION_SIZE) addr = MM_REGION_SIZE +| addr;

                const lo_off = imm_off;
                const hi_off = lo_off +| @as(usize, @intCast(INSN_SIZE));
                if (hi_off + BYTE_LENGTH_IMMEDIATE > elf_bytes.len)
                    return LoadError.ValueOutOfBounds;
                std.mem.writeInt(u32, elf_bytes[lo_off..][0..4], @truncate(addr & 0xffff_ffff), .little);
                std.mem.writeInt(u32, elf_bytes[hi_off..][0..4], @truncate(addr >> 32), .little);
            },

            R_BPF_64_RELATIVE => {
                const imm_off = r_off +| BYTE_OFFSET_IMMEDIATE;
                const in_text = (r_off >= text_start and r_off < text_end);
                if (in_text) {
                    const lo_off = imm_off;
                    const hi_off = r_off +| @as(usize, @intCast(INSN_SIZE)) +| BYTE_OFFSET_IMMEDIATE;
                    if (hi_off + BYTE_LENGTH_IMMEDIATE > elf_bytes.len)
                        return LoadError.ValueOutOfBounds;
                    const va_lo = std.mem.readInt(u32, elf_bytes[lo_off..][0..4], .little);
                    const va_hi = std.mem.readInt(u32, elf_bytes[hi_off..][0..4], .little);
                    var refd_addr: u64 = (@as(u64, va_hi) << 32) | @as(u64, va_lo);
                    if (refd_addr == 0) return LoadError.InvalidVirtualAddress;
                    if (refd_addr < MM_REGION_SIZE) refd_addr = MM_REGION_SIZE +| refd_addr;
                    std.mem.writeInt(u32, elf_bytes[lo_off..][0..4], @truncate(refd_addr & 0xffff_ffff), .little);
                    std.mem.writeInt(u32, elf_bytes[hi_off..][0..4], @truncate(refd_addr >> 32), .little);
                } else {
                    if (imm_off + BYTE_LENGTH_IMMEDIATE > elf_bytes.len)
                        return LoadError.ValueOutOfBounds;
                    const v = std.mem.readInt(u32, elf_bytes[imm_off..][0..4], .little);
                    var refd_addr: u64 = MM_REGION_SIZE +| @as(u64, v);
                    if (r_off + 8 > elf_bytes.len) return LoadError.ValueOutOfBounds;
                    std.mem.writeInt(u64, elf_bytes[r_off..][0..8], refd_addr, .little);
                    _ = &refd_addr;
                }
            },

            R_BPF_64_32 => {
                const imm_off = r_off +| BYTE_OFFSET_IMMEDIATE;
                if (imm_off + BYTE_LENGTH_IMMEDIATE > elf_bytes.len)
                    return LoadError.ValueOutOfBounds;
                const sym_idx = rel.rSym();
                if (sym_idx >= dynsym.len) return LoadError.UnknownSymbol;
                const sym = dynsym[sym_idx];
                const sname = readNulString(dynstr, sym.st_name);
                const is_func = (sym.st_info & 0x0f) == STT_FUNC;
                const key: u32 = if (is_func and sym.st_value != 0) blk: {
                    if (!(text_sh.sh_addr <= sym.st_value and
                        sym.st_value < text_sh.sh_addr +| text_sh.sh_size))
                    {
                        return LoadError.ValueOutOfBounds;
                    }
                    const target_pc: usize = @intCast(
                        (sym.st_value -| text_sh.sh_addr) / INSN_SIZE,
                    );
                    break :blk try registry.registerHashedLegacy(alloc, .v0, sname, target_pc);
                } else hashSymbolName(sname);
                if (cfg.reject_broken_elfs and !is_func) {
                    // Carrier #9 fix (@414537973): mirrors elf.rs:1129-1136 — a
                    // non-function import is a SYSCALL; Agave rejects only when
                    // the hash is absent from the LOADER's function registry.
                    // The old code checked the ELF's OWN registry (never holds
                    // syscalls) → UnknownSymbol for every program importing any
                    // syscall → cluster-accepted ExtendProgram failed in Vexor.
                    if (cfg.loader_syscall_keys) |keys| {
                        var found = false;
                        for (keys) |k| {
                            if (k == key) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) return LoadError.UnknownSymbol;
                    }
                    // No loader set supplied → skip the membership check (the
                    // pre-fix ELF-registry check was simply the wrong registry).
                }
                std.mem.writeInt(u32, elf_bytes[imm_off..][0..4], key, .little);
            },

            else => return LoadError.UnknownRelocation,
        }
    }
}

// ─── Section iteration helpers ────────────────────────────────────────────────

const SectionEntry = struct {
    shdr: Elf64Shdr,
    name: ?[]const u8,
};

const SectionIter = struct {
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
    shstrtab: ?Elf64Shdr,
    idx: u16 = 0,

    pub fn next(self: *SectionIter) LoadError!?SectionEntry {
        if (self.idx >= self.hdr.e_shnum) return null;
        const sh = (try readShdr(self.hdr, self.elf_bytes, self.idx)) orelse {
            self.idx += 1;
            return SectionEntry{ .shdr = std.mem.zeroes(Elf64Shdr), .name = null };
        };
        self.idx += 1;
        var name: ?[]const u8 = null;
        if (self.shstrtab) |sst| {
            name = readSectionName(self.elf_bytes, sst, sh.sh_name);
        }
        return SectionEntry{ .shdr = sh, .name = name };
    }
};

fn sectionIterator(hdr: *const Elf64Ehdr, elf_bytes: []const u8) SectionIter {
    const sst = readShdr(hdr, elf_bytes, hdr.e_shstrndx) catch null;
    return .{ .hdr = hdr, .elf_bytes = elf_bytes, .shstrtab = sst };
}

fn readShdr(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
    idx: u16,
) LoadError!?Elf64Shdr {
    if (idx >= hdr.e_shnum) return null;
    const off = hdr.e_shoff +| @as(u64, idx) *| @as(u64, hdr.e_shentsize);
    const end = off +| @sizeOf(Elf64Shdr);
    if (end > @as(u64, elf_bytes.len)) return LoadError.InvalidSectionHeader;
    var out: Elf64Shdr = undefined;
    @memcpy(std.mem.asBytes(&out), elf_bytes[@intCast(off)..@intCast(off + @sizeOf(Elf64Shdr))]);
    return out;
}

fn readSectionName(elf_bytes: []const u8, sst: Elf64Shdr, name_off: u32) ?[]const u8 {
    const start = sst.sh_offset +| @as(u64, name_off);
    if (start >= @as(u64, elf_bytes.len)) return null;
    var end: usize = @intCast(start);
    while (end < elf_bytes.len and elf_bytes[end] != 0) end += 1;
    return elf_bytes[@intCast(start)..end];
}

fn readNulString(strtab: []const u8, name_off: u32) []const u8 {
    if (name_off >= strtab.len) return "";
    var end: usize = name_off;
    while (end < strtab.len and strtab[end] != 0) end += 1;
    return strtab[name_off..end];
}

fn findSectionByName(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
    name: []const u8,
) LoadError!?Elf64Shdr {
    var it = sectionIterator(hdr, elf_bytes);
    while (try it.next()) |entry| {
        if (entry.name) |n| if (std.mem.eql(u8, n, name)) return entry.shdr;
    }
    return null;
}

// ─── Dynamic relocation table discovery (best effort) ─────────────────────────

fn findDynamicRelas(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
) LoadError![]align(1) const Elf64Rel {
    // Canonical relocation table = DT_REL → SHT_REL (Elf64Rel, NO addend). Both
    // Agave (anza-sbpf v0.21.0 elf_parser parse_dynamic_relocations reads DT_REL
    // ONLY; elf.rs applies dynamic_relocations_table()) and Firedancer
    // (fd_sbpf_loader.c:380 "the relocation table (via DT_REL) is used") process
    // SHT_REL exclusively and NEVER SHT_RELA. The Solana toolchain emits SHT_REL.
    //
    // Audit-#6 resolution (2026-06-18): the prior code accepted SHT_RELA and
    // returned `&.{}` on it — which not only failed to process RELA but, if a
    // SHT_RELA section preceded the real .rel.dyn in section order, BAILED early
    // and suppressed the SHT_REL relocations entirely. We now SKIP SHT_RELA (not
    // bail), so a later SHT_REL is still found — matching canonical exactly.
    // NOTE: we deliberately do NOT process SHT_RELA; doing so would DIVERGE from
    // canonical (relocate entries the cluster leaves untouched). No-op for every
    // well-formed program (which carries only .rel.dyn / SHT_REL).
    var it = sectionIterator(hdr, elf_bytes);
    while (try it.next()) |entry| {
        if (entry.shdr.sh_type != SHT_REL) continue;
        const off = entry.shdr.sh_offset;
        const sz = entry.shdr.sh_size;
        if (sz == 0 or (sz % @sizeOf(Elf64Rel)) != 0) return &.{};
        const end = std.math.add(u64, off, sz) catch return LoadError.ValueOutOfBounds;
        if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
        return std.mem.bytesAsSlice(
            Elf64Rel,
            @as([]align(1) const u8, elf_bytes[@intCast(off)..@intCast(end)]),
        );
    }
    return &.{};
}

fn symbolTableOfType(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
    want_type: u32,
) LoadError!?[]align(1) const Elf64Sym {
    var it = sectionIterator(hdr, elf_bytes);
    while (try it.next()) |entry| {
        if (entry.shdr.sh_type != want_type) continue;
        const off = entry.shdr.sh_offset;
        const sz = entry.shdr.sh_size;
        if (sz == 0 or (sz % @sizeOf(Elf64Sym)) != 0) continue;
        const end = std.math.add(u64, off, sz) catch return LoadError.ValueOutOfBounds;
        if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
        return std.mem.bytesAsSlice(
            Elf64Sym,
            @as([]align(1) const u8, elf_bytes[@intCast(off)..@intCast(end)]),
        );
    }
    return null;
}

fn findDynsym(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
) LoadError![]align(1) const Elf64Sym {
    // Canonical: the relocation symbol table is the DYNAMIC symbol table at
    // DT_SYMTAB, which is the SHT_DYNSYM section (.dynsym). A static .symtab
    // (SHT_SYMTAB) is NOT the relocation symbol table.
    //
    // Audit-#5 fix (2026-06-18): PREFER SHT_DYNSYM. The old code returned the
    // FIRST section of type SHT_DYNSYM **or SHT_SYMTAB** → if a .symtab preceded
    // .dynsym in section order it grabbed the wrong table → wrong symbol names →
    // wrong syscall-hash keys → divergence. Now we take .dynsym (SHT_DYNSYM) and
    // fall back to SHT_SYMTAB only when no .dynsym exists (degenerate). Mirrors
    // Agave (elf_parser parse_dynamic_symbol_table via DT_SYMTAB) + Firedancer
    // (fd_sbpf_loader.c:1285-1307, validates SHT_SYMTAB||SHT_DYNSYM at DT_SYMTAB).
    // No-op for every well-formed program (single .dynsym, no .symtab).
    if (try symbolTableOfType(hdr, elf_bytes, SHT_DYNSYM)) |s| return s;
    if (try symbolTableOfType(hdr, elf_bytes, SHT_SYMTAB)) |s| return s;
    return &.{};
}

fn findDynstr(
    hdr: *const Elf64Ehdr,
    elf_bytes: []const u8,
) LoadError![]const u8 {
    // Canonical: the dynamic string table is the section NAMED ".dynstr" (Agave
    // elf_parser binds b".dynstr" by name → dynamic_symbol_names_section_header;
    // Firedancer fd_sbpf_loader.c:1133 records shndx_dynstr by the ".dynstr"
    // name). Audit-#5 fix (2026-06-18): bind ".dynstr" by name so a preceding
    // .strtab cannot be mis-selected. Fall back to the legacy "first non-shstrtab
    // STRTAB" heuristic ONLY when ".dynstr" is absent (canonical errors there; we
    // stay lenient + preserve prior behavior). No-op for every well-formed
    // program (which carries a ".dynstr"; the legacy heuristic already returned
    // it as the sole non-shstrtab STRTAB).
    if (try findSectionByName(hdr, elf_bytes, ".dynstr")) |sh| {
        if (sh.sh_type == SHT_STRTAB) {
            const off = sh.sh_offset;
            const sz = sh.sh_size;
            const end = std.math.add(u64, off, sz) catch return LoadError.ValueOutOfBounds;
            if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
            return elf_bytes[@intCast(off)..@intCast(end)];
        }
    }
    // Legacy fallback: first STRTAB section that is NOT the section-name strtab.
    const sst_idx = hdr.e_shstrndx;
    var it = sectionIterator(hdr, elf_bytes);
    var best: ?Elf64Shdr = null;
    var idx: u16 = 0;
    while (try it.next()) |entry| : (idx += 1) {
        if (entry.shdr.sh_type != SHT_STRTAB) continue;
        if (idx == sst_idx) continue;
        best = entry.shdr;
        break;
    }
    const sh = best orelse return &.{};
    const off = sh.sh_offset;
    const sz = sh.sh_size;
    const end = std.math.add(u64, off, sz) catch return LoadError.ValueOutOfBounds;
    if (end > @as(u64, elf_bytes.len)) return LoadError.ValueOutOfBounds;
    return elf_bytes[@intCast(off)..@intCast(end)];
}

// ─── Inline tests (Stage-A subset; full test surface in elf_test.zig) ─────────

test "hashSymbolName parity (Murmur3_32 seed=0)" {
    try std.testing.expectEqual(@as(u32, 0x207559bd), hashSymbolName("sol_log_"));
    try std.testing.expectEqual(@as(u32, 0x11f49d86), hashSymbolName("sol_sha256"));
}

test "Config.versionEnabled bitset" {
    var c: Config = .{};
    try std.testing.expect(c.versionEnabled(.v0));
    try std.testing.expect(c.versionEnabled(.v3));
    c.enabled_sbpf_versions = 0b0001;
    try std.testing.expect(c.versionEnabled(.v0));
    try std.testing.expect(!c.versionEnabled(.v1));
}

test "loadInner: too short → OutOfBounds" {
    const bad = [_]u8{0} ** 8;
    try std.testing.expectError(
        LoadError.OutOfBounds,
        loadInner(std.testing.allocator, bad[0..], Config.DEFAULT),
    );
}

test "loadInner: bad e_flags → UnsupportedSbpfVersion" {
    var bytes: [@sizeOf(Elf64Ehdr)]u8 = undefined;
    @memset(bytes[0..], 0);
    // Magic OK so we exercise the e_flags read.
    bytes[0] = 0x7F;
    bytes[1] = 0x45;
    bytes[2] = 0x4C;
    bytes[3] = 0x46;
    // e_flags = 999 (out of range)
    std.mem.writeInt(u32, bytes[48..52], 999, .little);
    try std.testing.expectError(
        LoadError.UnsupportedSbpfVersion,
        loadInner(std.testing.allocator, bytes[0..], Config.DEFAULT),
    );
}

// ─── Audit-#5 KAT: findDynsym/findDynstr prefer .dynsym/.dynstr ────────────────
//
// Proves the 2026-06-18 ELF-loader bug-#5 fix on the adversarial layout it
// targets: a static `.symtab` (SHT_SYMTAB) placed at a LOWER section index than
// the dynamic `.dynsym` (SHT_DYNSYM), and a `.strtab` (SHT_STRTAB) at a lower
// index than `.dynstr` (SHT_STRTAB, named ".dynstr"). The OLD "first-of-type"
// code returned the FIRST SHT_DYNSYM-OR-SHT_SYMTAB section and the FIRST
// non-shstrtab STRTAB → it would grab the preceding .symtab/.strtab → wrong
// symbol names → wrong syscall-hash keys → bank_hash divergence. The fix PREFERS
// SHT_DYNSYM and binds ".dynstr" by name. Ordering (symtab < dynsym,
// strtab < dynstr) is precisely what the old code got wrong, so it is load-
// bearing here.
//
// These fns parse ONLY section headers off `hdr.e_shoff`; they never read the
// Ehdr from `elf_bytes` and never validate e_machine/e_flags. So we hand the
// real Ehdr as a struct and only put the section-header table + tiny blobs into
// `elf_bytes`. Everything is built programmatically (no hand-counted offsets).

/// Builder for a tiny section-header-only ELF image used by the KAT below.
/// `elf_bytes` layout: [ shstrtab name blob | per-section data blobs |
/// section-header table ]. The Ehdr is returned separately (its e_shoff points
/// into elf_bytes); the helpers under test read only via that Ehdr.
const KatElf = struct {
    bytes: std.ArrayListUnmanaged(u8) = .{},
    shdrs: std.ArrayListUnmanaged(Elf64Shdr) = .{},
    shstr: std.ArrayListUnmanaged(u8) = .{},
    alloc: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator) !KatElf {
        var k: KatElf = .{ .alloc = alloc };
        // Index 0 == name offset 0 == empty string (ELF convention).
        try k.shstr.append(alloc, 0);
        return k;
    }

    fn deinit(self: *KatElf) void {
        self.bytes.deinit(self.alloc);
        self.shdrs.deinit(self.alloc);
        self.shstr.deinit(self.alloc);
    }

    /// Intern a section name into the shstrtab blob, returning its byte offset.
    fn internName(self: *KatElf, name: []const u8) !u32 {
        const off: u32 = @intCast(self.shstr.items.len);
        try self.shstr.appendSlice(self.alloc, name);
        try self.shstr.append(self.alloc, 0);
        return off;
    }

    /// Append a data blob to `bytes`, returning its absolute file offset.
    fn appendBlob(self: *KatElf, blob: []const u8) !u64 {
        const off: u64 = @intCast(self.bytes.items.len);
        try self.bytes.appendSlice(self.alloc, blob);
        return off;
    }

    /// Register a section header. `data_off`/`size` reference an already-
    /// appended blob (or 0/0 for SHT_NULL). Returns the section index.
    fn addSection(self: *KatElf, name: []const u8, sh_type: u32, data_off: u64, size: u64) !u16 {
        const name_off = if (name.len == 0) @as(u32, 0) else try self.internName(name);
        const idx: u16 = @intCast(self.shdrs.items.len);
        try self.shdrs.append(self.alloc, std.mem.zeroes(Elf64Shdr));
        const sh = &self.shdrs.items[idx];
        sh.sh_name = name_off;
        sh.sh_type = sh_type;
        sh.sh_offset = data_off;
        sh.sh_size = size;
        return idx;
    }

    /// Finalize: append the shstrtab blob + a section for it, then append the
    /// section-header table to the end of `bytes`. Returns the Ehdr (pointing
    /// e_shoff at the appended table) and the backing bytes via self.bytes.
    fn finish(self: *KatElf) !Elf64Ehdr {
        // The shstrtab is itself a section; place its blob then its header.
        const shstr_off = try self.appendBlob(self.shstr.items);
        const shstr_idx: u16 = @intCast(self.shdrs.items.len);
        // ".shstrtab" name must live IN the shstrtab; intern it (extends shstr)
        // BEFORE we froze the blob, so re-append the (now longer) blob and point
        // at the fresh copy.
        const shstr_name_off = try self.internName(".shstrtab");
        const shstr_off2 = try self.appendBlob(self.shstr.items);
        try self.shdrs.append(self.alloc, std.mem.zeroes(Elf64Shdr));
        const sh = &self.shdrs.items[shstr_idx];
        sh.sh_name = shstr_name_off;
        sh.sh_type = SHT_STRTAB;
        sh.sh_offset = shstr_off2;
        sh.sh_size = @intCast(self.shstr.items.len);
        _ = shstr_off;

        const sh_table_off: u64 = @intCast(self.bytes.items.len);
        for (self.shdrs.items) |shdr| {
            try self.bytes.appendSlice(self.alloc, std.mem.asBytes(&shdr));
        }

        var ehdr = std.mem.zeroes(Elf64Ehdr);
        ehdr.e_shoff = sh_table_off;
        ehdr.e_shentsize = @sizeOf(Elf64Shdr);
        ehdr.e_shnum = @intCast(self.shdrs.items.len);
        ehdr.e_shstrndx = shstr_idx;
        return ehdr;
    }
};

fn katSym(st_name: u32) Elf64Sym {
    var s = std.mem.zeroes(Elf64Sym);
    s.st_name = st_name;
    return s;
}

test "findDynsym/findDynstr: prefer .dynsym/.dynstr over preceding .symtab/.strtab (audit-#5)" {
    const a = std.testing.allocator;

    // Distinguishable symbol blobs: symtab has 2 syms (st_name 0x1111/0x1112),
    // dynsym has 1 sym (st_name 0x2222). Distinct st_name + distinct count.
    const symtab_blob = [_]Elf64Sym{ katSym(0x1111), katSym(0x1112) };
    const dynsym_blob = [_]Elf64Sym{katSym(0x2222)};
    // Distinct string blobs.
    const strtab_blob = "ABCstrtab\x00";
    const dynstr_blob = "XYZdynstr\x00";

    var k = try KatElf.init(a);
    defer k.deinit();

    // Index 0: SHT_NULL (ELF convention).
    _ = try k.addSection("", SHT_NULL, 0, 0);

    // Adversarial order: .symtab BEFORE .dynsym, .strtab BEFORE .dynstr.
    const symtab_off = try k.appendBlob(std.mem.sliceAsBytes(symtab_blob[0..]));
    _ = try k.addSection(".symtab", SHT_SYMTAB, symtab_off, @sizeOf(Elf64Sym) * symtab_blob.len);

    const strtab_off = try k.appendBlob(strtab_blob);
    _ = try k.addSection(".strtab", SHT_STRTAB, strtab_off, strtab_blob.len);

    const dynsym_off = try k.appendBlob(std.mem.sliceAsBytes(dynsym_blob[0..]));
    _ = try k.addSection(".dynsym", SHT_DYNSYM, dynsym_off, @sizeOf(Elf64Sym) * dynsym_blob.len);

    const dynstr_off = try k.appendBlob(dynstr_blob);
    _ = try k.addSection(".dynstr", SHT_STRTAB, dynstr_off, dynstr_blob.len);

    const ehdr = try k.finish();

    // findDynsym must return the .dynsym table (1 sym, st_name 0x2222), NOT the
    // earlier .symtab (2 syms, st_name 0x1111). The OLD code returned .symtab.
    const got_sym = try findDynsym(&ehdr, k.bytes.items);
    try std.testing.expectEqual(@as(usize, 1), got_sym.len);
    try std.testing.expectEqual(@as(u32, 0x2222), got_sym[0].st_name);

    // findDynstr must return the .dynstr bytes, NOT the earlier .strtab. The OLD
    // code returned the first non-shstrtab STRTAB == .strtab.
    const got_str = try findDynstr(&ehdr, k.bytes.items);
    try std.testing.expectEqualSlices(u8, dynstr_blob, got_str);
}

test "findDynsym/findDynstr: no-op control — only .dynsym/.dynstr (canonical layout)" {
    const a = std.testing.allocator;

    const dynsym_blob = [_]Elf64Sym{katSym(0x2222)};
    const dynstr_blob = "XYZdynstr\x00";

    var k = try KatElf.init(a);
    defer k.deinit();

    _ = try k.addSection("", SHT_NULL, 0, 0);

    const dynsym_off = try k.appendBlob(std.mem.sliceAsBytes(dynsym_blob[0..]));
    _ = try k.addSection(".dynsym", SHT_DYNSYM, dynsym_off, @sizeOf(Elf64Sym) * dynsym_blob.len);

    const dynstr_off = try k.appendBlob(dynstr_blob);
    _ = try k.addSection(".dynstr", SHT_STRTAB, dynstr_off, dynstr_blob.len);

    const ehdr = try k.finish();

    // Canonical single-table layout resolves the same way before and after the
    // fix: .dynsym and .dynstr are selected exactly.
    const got_sym = try findDynsym(&ehdr, k.bytes.items);
    try std.testing.expectEqual(@as(usize, 1), got_sym.len);
    try std.testing.expectEqual(@as(u32, 0x2222), got_sym[0].st_name);

    const got_str = try findDynstr(&ehdr, k.bytes.items);
    try std.testing.expectEqualSlices(u8, dynstr_blob, got_str);
}
