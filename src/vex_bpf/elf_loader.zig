//! BPF ELF Loader
//! Parses ELF64 binaries containing eBPF bytecode for Solana programs.
//!
//! Solana programs are compiled to eBPF (extended Berkeley Packet Filter)
//! and stored as ELF64 files. This loader extracts the bytecode and
//! relocation information needed for execution.

const std = @import("std");
const Allocator = std.mem.Allocator;
const SbpfVersion = @import("vm.zig").SbpfVersion;
const VM_RODATA_START = @import("vm.zig").VM_RODATA_START;
/// r71-fix-7e: pull murmur3 from vm_executable.zig (V2's helper, already
/// validated against Agave/sig — see "murmur3: known syscall IDs" test).
const murmur3 = @import("murmur3.zig").murmur3; // module-67 §G SPLIT: was @import("vm_executable.zig").murmur3 — repointed to the byte-exact extraction so the LIVE loader doesn't pull the API-rotted DELETE-bound vm_executable.zig (see murmur3.zig header)

/// r48-A-rev2 (2026-04-27): parse ELF e_flags to identify the BPF version.
/// Solana ELF e_flags encoding: 0=v0 (legacy), 1=v1 (SIMD-0166), 2=v2 (SIMD-0173/4),
/// 3=v3 (SIMD-0178/9/89: static syscalls + bytecode-vaddr=0). Pre-r48-A-rev2,
/// HEAD's sbpf_executor.zig:132 hardcoded `.v1` for ALL programs regardless of
/// actual ELF version → V3 programs got AccessViolation at first instruction
/// fetch because vm.MemoryMap.init(.v3, ...) maps bytecode at vaddr 0 (per
/// `enableLowerBytecodeVaddr()` predicate) while the executor told it `.v1`
/// which expects bytecode at RODATA_START. vex-061's "0/10864 BPF executions
/// had mutations>0" symptom traced back here. vex-oracle.py 2026-04-27 ranked
/// WRITES at 99.1% of slots — exactly the writeset deficit caused by silent BPF
/// failures.
fn parseSbpfVersionFromEflags(e_flags: u32) SbpfVersion {
    return switch (e_flags) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => .v1, // unknown e_flags → fall back to v1 (matches pre-r48-A-rev2 behavior)
    };
}

/// ELF64 Header
pub const Elf64Header = extern struct {
    e_ident: [16]u8,
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

/// ELF64 Section Header
pub const Elf64SectionHeader = extern struct {
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

/// ELF64 Program Header
pub const Elf64ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

/// ELF64 Symbol
pub const Elf64Symbol = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

/// ELF64 Relocation with addend
/// ELF64 Relocation without addend (REL format, 16 bytes).
/// Used by Solana sBPF v0 programs in `.rel.dyn` for both call_imm
/// patching (R_BPF_INSN_DISP32 = 10) and rodata fixups (R_BPF_DATA_8 = 8).
pub const Elf64Rel = extern struct {
    r_offset: u64,
    r_info: u64,

    pub fn getSymbol(self: *const Elf64Rel) u32 {
        return @truncate(self.r_info >> 32);
    }

    pub fn getType(self: *const Elf64Rel) u32 {
        return @truncate(self.r_info & 0xffffffff);
    }
};

pub const Elf64Rela = extern struct {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,

    pub fn getSymbol(self: *const Elf64Rela) u32 {
        return @truncate(self.r_info >> 32);
    }

    pub fn getType(self: *const Elf64Rela) u32 {
        return @truncate(self.r_info & 0xffffffff);
    }
};

/// ELF magic bytes
const ELF_MAGIC = [4]u8{ 0x7f, 'E', 'L', 'F' };

/// ELF class (64-bit)
const ELFCLASS64: u8 = 2;

/// ELF data encoding (little endian)
const ELFDATA2LSB: u8 = 1;

/// ELF machine type for BPF (legacy)
const EM_BPF: u16 = 247;
/// ELF machine type for sBPF (newer Solana programs).
/// firedancer/src/ballet/elf/fd_elf.h:55 (FD_ELF_EM_SBPF = 263)
/// firedancer/src/ballet/sbpf/fd_sbpf_loader.c:1357 — accepts BOTH 247 and 263
/// Vexor V1 had only EM_BPF = 247 → newer programs (e.g., 065afb9d) returned
/// InvalidMachine and silently dropped; mutations=0 cascaded into bank_hash drift.
const EM_SBPF: u16 = 263;

/// Section types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;

/// Section flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// Program header types
const PT_LOAD: u32 = 1;

/// Loaded BPF program — ready to pass to fd_vm_init.
///
/// Firedancer's fd_vm_init requires a single contiguous "rodata" buffer that
/// contains BOTH the .text section (executable bytecode) and .rodata section
/// (read-only data), laid out as they appear in the ELF virtual address space.
///
/// Fields:
///   rodata_combined  — flat buffer covering all ALLOC sections (fd_vm_init "rodata")
///   text_offset      — byte offset of .text within rodata_combined (fd_vm_init "text_off")
///   text_size        — size of .text in bytes (fd_vm_init "text_sz")
///   entry_pc         — entry point as BPF instruction index, 0-based (fd_vm_init "entry_pc")
///                      = (e_entry - .text.sh_addr) / 8
pub const LoadedProgram = struct {
    /// Combined flat buffer: all ELF ALLOC sections in virtual-address order.
    /// .text lives at rodata_combined[text_offset..text_offset+text_size].
    rodata_combined: []u8,
    /// Byte offset of .text within rodata_combined.
    text_offset: u64,
    /// Size of .text in bytes.
    text_size: u64,
    /// Entry point as instruction index (0-based) within .text.
    /// entry_pc = (e_entry - text_vaddr) / 8
    entry_pc: u64,
    /// r48-A-rev2 (2026-04-27): sBPF version parsed from ELF e_flags.
    /// Threaded into VmContext.init at sbpf_executor.zig instead of hardcoded .v1.
    /// V3 programs need this for `enableLowerBytecodeVaddr` to map bytecode at vaddr 0.
    sbpf_version: SbpfVersion,
    /// r75-bug-class-b-2026-05-06: V0/V1/V2 lenient-ELF rodata vaddr parity.
    /// Port of vex_bpf2 commit 21298a3 ("fix(vex_bpf2): correct rodata vmaddr
    /// for V0 lenient ELFs"). The MemoryMap region for rodata MUST be created
    /// at this vaddr — NOT hardcoded VM_RODATA_START — otherwise every rodata
    /// read shifts by `base_vaddr` bytes. For HistoryJT (.text sh_addr=0x120)
    /// the shift is 288 bytes; Anchor's #[account(seeds=...)] reads garbage
    /// strings → wrong PDA → ConstraintSeeds → panic-handler CALLX r4 →
    /// wild-pointer LDX_64 fault. Equals VM_RODATA_START for V3 (base_vaddr=0).
    rodata_vaddr: u64,
    /// Symbol table for syscall resolution (keyed by name → virtual address)
    symbols: std.StringHashMap(u64),
    /// r71-fix-7e: function registry for v0/v1/v2 `call imm` dispatch.
    /// Maps murmur3_32(symbol_name) → instruction-index PC of the function entry.
    /// sBPF v0/v1/v2 encode local function calls with imm = murmur3 hash; the
    /// interpreter must look this up to translate to a PC. Without it, the
    /// fallback `vm.pc = imm` (vm.zig:819 pre-fix) would set pc to the hash
    /// (a giant number) and the next step() would hit out-of-text and fail
    /// with InvalidInstruction. r71-fix-7d (MEM mode) revealed this as the
    /// next-layer bug because programs now decode loads/stores correctly but
    /// then crash on local function calls. Mirrors v2's vm_executable.zig
    /// FunctionRegistry but stays in the V1 module to avoid cross-stack deps.
    function_registry: std.AutoHashMapUnmanaged(u32, u64),
    /// Allocator used
    allocator: Allocator,

    pub fn deinit(self: *LoadedProgram) void {
        self.allocator.free(self.rodata_combined);
        var it = self.symbols.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.symbols.deinit();
        self.function_registry.deinit(self.allocator);
    }
};

/// ELF loading errors
pub const ElfError = error{
    InvalidMagic,
    InvalidClass,
    InvalidEncoding,
    InvalidMachine,
    InvalidVersion,
    NoTextSection,
    SectionOutOfBounds,
    InvalidSectionHeader,
    InvalidSymbol,
    RelocationFailed,
    OutOfMemory,
    InvalidElfData,
};

/// ELF Loader for BPF programs
pub const ElfLoader = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) ElfLoader {
        return .{ .allocator = allocator };
    }

    /// Load a BPF program from ELF data.
    ///
    /// Produces a LoadedProgram whose fields map directly to fd_vm_init parameters:
    ///   rodata_combined -> rodata / rodata_sz
    ///   text_offset     -> text_off
    ///   text_size       -> text_sz  (text_cnt = text_size / 8)
    ///   entry_pc        -> entry_pc
    ///
    /// The combined rodata buffer contains all ALLOC sections in virtual-address
    /// order. .text lives inside it at offset text_offset.
    pub fn load(self: *ElfLoader, raw_elf_data: []const u8) ElfError!LoadedProgram {
        if (raw_elf_data.len < @sizeOf(Elf64Header)) return ElfError.InvalidElfData;

        // Ensure 8-byte alignment for Elf64 structures. Data from AppendVec is often unaligned.
        var aligned_buffer: ?[]align(8) u8 = null;
        const elf_data = if (@intFromPtr(raw_elf_data.ptr) % 8 == 0)
            @as([]align(8) const u8, @alignCast(raw_elf_data))
        else blk: {
            aligned_buffer = self.allocator.alignedAlloc(u8, .@"8", raw_elf_data.len) catch return ElfError.OutOfMemory;
            @memcpy(aligned_buffer.?, raw_elf_data);
            break :blk aligned_buffer.?;
        };
        defer if (aligned_buffer) |buf| self.allocator.free(buf);

        const header: *const Elf64Header = @ptrCast(elf_data.ptr);
        if (!std.mem.eql(u8, header.e_ident[0..4], &ELF_MAGIC)) return ElfError.InvalidMagic;
        if (header.e_ident[4] != ELFCLASS64) return ElfError.InvalidClass;
        if (header.e_ident[5] != ELFDATA2LSB) return ElfError.InvalidEncoding;
        if (header.e_machine != EM_BPF and header.e_machine != EM_SBPF) return ElfError.InvalidMachine;

        const shstrtab_offset = self.getSectionOffset(elf_data, header, header.e_shstrndx) orelse
            return ElfError.InvalidSectionHeader;

        // Pass 1: find virtual address range of all ALLOC sections
        var base_vaddr: u64 = std.math.maxInt(u64);
        var top_vaddr: u64 = 0;
        var text_section: ?*const Elf64SectionHeader = null;
        var symtab_section: ?*const Elf64SectionHeader = null;
        var strtab_section: ?*const Elf64SectionHeader = null;
        // r71-fix-7g: dynamic symbol/string tables + .rela.text section.
        // Solana programs encode external syscall calls (sol_log_, sol_memcpy_,
        // sol_invoke_signed_*, etc.) by emitting `call -1` (imm = 0xFFFFFFFF)
        // in the bytecode, with a corresponding entry in .rela.text of type
        // R_BPF_64_32 referencing a symbol in .dynsym. The loader is supposed
        // to patch each call_imm's imm field with murmur3_32(symbol_name).
        // Without this pass, runtime call_imm dispatch sees imm=-1, which my
        // r71-fix-7f relative-offset fallback computes as `pc + (-1) + 1 = pc`
        // → infinite recursion → StackOverflow (observed in all 3 slot-484
        // programs). Mirrors sig/src/vm/elf.zig:870-916.
        var dynsym_section: ?*const Elf64SectionHeader = null;
        var dynstr_section: ?*const Elf64SectionHeader = null;
        var rela_text_section: ?*const Elf64SectionHeader = null;
        // r71-fix-7h: real Solana sBPF v0 programs put their relocations in
        // `.rel.dyn` (Elf64Rel — 16 bytes, no r_addend) rather than
        // `.rela.text` (Elf64Rela — 24 bytes). Haiku-agent ELF inspection
        // 2026-04-28 confirmed: 78× type-10 (R_BPF_INSN_DISP32) entries +
        // 317× type-8 (R_BPF_DATA_8) entries in .rel.dyn for representative
        // programs. r71-fix-7g only handled .rela.text → never fired on real
        // programs → all 92 StackOverflow events at imm=-1 persisted.
        var rel_dyn_section: ?*const Elf64SectionHeader = null;

        {
            var i: u16 = 0;
            while (i < header.e_shnum) : (i += 1) {
                const sh = self.getSectionHeader(elf_data, header, i) orelse continue;
                const name = self.getSectionName(elf_data, shstrtab_offset, sh.sh_name);
                if ((sh.sh_flags & SHF_ALLOC) != 0 and sh.sh_size > 0) {
                    if (sh.sh_addr < base_vaddr) base_vaddr = sh.sh_addr;
                    const top = sh.sh_addr + sh.sh_size;
                    if (top > top_vaddr) top_vaddr = top;
                }
                if (std.mem.eql(u8, name, ".text")) {
                    text_section = sh;
                } else if (sh.sh_type == SHT_SYMTAB) {
                    symtab_section = sh;
                } else if (sh.sh_type == SHT_STRTAB and !std.mem.eql(u8, name, ".shstrtab") and !std.mem.eql(u8, name, ".dynstr")) {
                    // r71-fix-10 (2026-04-28): exclude `.dynstr` from generic
                    // SHT_STRTAB capture. Without this exclusion the else-if
                    // chain assigned `.dynstr` to `strtab_section` (because it
                    // is sh_type=3) BEFORE the explicit name check below could
                    // run. `dynstr_section` stayed null → the `.rel.dyn`
                    // relocation pass guard `if (rel_dyn_section != null and
                    // dynsym_section != null and dynstr_section != null)` was
                    // false → no syscall-stub `call -1` (imm=0xffffffff) in
                    // any real Solana program ever got patched to its
                    // murmur3_32(symbol_name) hash. r71-fix-7h's claim that
                    // .rel.dyn was "working" was false — every program
                    // lacking a separate `.strtab` (i.e. all of them) hit
                    // this. Carrier: 5093+ [BPF-OPC] imm=0xffffffff events
                    // for prog=e34d/065a/8c97/etc at slots 484+.
                    strtab_section = sh;
                } else if (std.mem.eql(u8, name, ".dynsym")) {
                    dynsym_section = sh;
                } else if (std.mem.eql(u8, name, ".dynstr")) {
                    dynstr_section = sh;
                } else if (std.mem.eql(u8, name, ".rela.text")) {
                    rela_text_section = sh;
                } else if (std.mem.eql(u8, name, ".rel.dyn")) {
                    rel_dyn_section = sh;
                }
            }
        }

        const text = text_section orelse return ElfError.NoTextSection;
        if (base_vaddr == std.math.maxInt(u64) or top_vaddr <= base_vaddr)
            return ElfError.InvalidElfData;

        const combined_size = top_vaddr - base_vaddr;
        if (combined_size > 64 * 1024 * 1024) return ElfError.InvalidElfData; // sanity: max 64MB

        // Pass 2: build combined flat buffer in virtual-address order
        const combined = self.allocator.alloc(u8, combined_size) catch
            return ElfError.OutOfMemory;
        errdefer self.allocator.free(combined);
        @memset(combined, 0);

        {
            var i: u16 = 0;
            while (i < header.e_shnum) : (i += 1) {
                const sh = self.getSectionHeader(elf_data, header, i) orelse continue;
                if ((sh.sh_flags & SHF_ALLOC) == 0 or sh.sh_size == 0) continue;
                if (sh.sh_type == SHT_NOBITS) continue; // .bss — leave as zeros
                const buf_off = sh.sh_addr - base_vaddr;
                const file_end = sh.sh_offset + sh.sh_size;
                if (file_end > elf_data.len) return ElfError.SectionOutOfBounds;
                if (buf_off + sh.sh_size > combined_size) return ElfError.SectionOutOfBounds;
                @memcpy(combined[buf_off..][0..sh.sh_size], elf_data[sh.sh_offset..file_end]);
            }
        }

        // r71-fix-7e/g: function_registry built ahead of relocation pass so
        // that R_BPF_64_32 entries pointing to internal STT_FUNC symbols get
        // their PC entries registered as the imm gets patched.
        var function_registry: std.AutoHashMapUnmanaged(u32, u64) = .{};
        errdefer function_registry.deinit(self.allocator);

        // r71-fix-7g: apply R_BPF_64_32 relocations to `combined`. Each entry
        // patches the imm field (4 bytes at r_offset+4) of a call_imm
        // instruction with murmur3_32(symbol_name) so that runtime dispatch
        // matches the registered syscalls table. Other relocation types
        // (R_BPF_64_64, R_BPF_64_RELATIVE) are deferred — they're for rodata
        // address fixups, not call dispatch; programs that depend on them
        // would still fail later, but the slot-484 carrier is call dispatch.
        if (rela_text_section != null and dynsym_section != null and dynstr_section != null) {
            const rela_sh = rela_text_section.?;
            const dynsym_sh = dynsym_section.?;
            const dynstr_sh = dynstr_section.?;
            const rela_count = rela_sh.sh_size / @sizeOf(Elf64Rela);
            const dynsym_count = dynsym_sh.sh_size / @sizeOf(Elf64Symbol);

            var ri: usize = 0;
            while (ri < rela_count) : (ri += 1) {
                const r_off = rela_sh.sh_offset + ri * @sizeOf(Elf64Rela);
                if (r_off + @sizeOf(Elf64Rela) > elf_data.len) break;
                const rela: *const Elf64Rela = @ptrCast(@alignCast(elf_data.ptr + r_off));
                const r_type = rela.getType();
                const r_sym = rela.getSymbol();
                // R_BPF_64_32 = 10. Only handle that for the call-dispatch fix.
                if (r_type != 10) continue;
                if (r_sym >= dynsym_count) continue;

                const sym_off = dynsym_sh.sh_offset + r_sym * @sizeOf(Elf64Symbol);
                if (sym_off + @sizeOf(Elf64Symbol) > elf_data.len) continue;
                const sym: *const Elf64Symbol = @ptrCast(@alignCast(elf_data.ptr + sym_off));
                const sym_name = self.getStringFromTable(elf_data, dynstr_sh.sh_offset, sym.st_name);
                if (sym_name.len == 0) continue;

                // r_offset is a virtual address inside the loaded image.
                // Patch happens at offset 4 of the 8-byte instruction (the imm
                // field of `call imm` is the high 4 bytes after opcode/dst/src/off).
                const target_vaddr = rela.r_offset;
                if (target_vaddr < base_vaddr) continue;
                const buf_off = target_vaddr - base_vaddr;
                if (buf_off + 8 > combined_size) continue;

                // For STT_FUNC inside .text → register PC and patch imm with the
                // hash key. For external syscalls → patch imm with the murmur3
                // hash so syscalls.get(imm) hits at runtime.
                const is_func_in_text = (sym.st_info & 0x0f) == 2 and sym.st_value != 0 and sym.st_value >= text.sh_addr and sym.st_value < text.sh_addr + text.sh_size;

                const hash: u32 = if (is_func_in_text) blk: {
                    const target_pc = (sym.st_value - text.sh_addr) / 8;
                    const h = murmur3(sym_name);
                    function_registry.put(self.allocator, h, target_pc) catch {};
                    break :blk h;
                } else murmur3(sym_name);

                std.mem.writeInt(u32, combined[buf_off + 4 ..][0..4], hash, .little);
            }
        }

        // r71-fix-7h: parallel pass over `.rel.dyn` (REL — 16-byte entries
        // without addend). Solana sBPF v0 programs put their relocations here
        // rather than .rela.text. Same handling as above for type 10
        // (R_BPF_INSN_DISP32 = call_imm patch) — the mechanism + symbol
        // lookup is identical, only the entry stride differs.
        if (rel_dyn_section != null and dynsym_section != null and dynstr_section != null) {
            const rel_sh = rel_dyn_section.?;
            const dynsym_sh = dynsym_section.?;
            const dynstr_sh = dynstr_section.?;
            const rel_count = rel_sh.sh_size / @sizeOf(Elf64Rel);
            const dynsym_count = dynsym_sh.sh_size / @sizeOf(Elf64Symbol);

            // r75-bug-class-b-2026-05-06: also handle R_BPF_64_RELATIVE (type 8)
            // alongside R_BPF_64_32 (type 10). 1667 type-8 entries in deployed
            // Jito tip-payment v0.1.5 ELF — without these, rodata pointers stay
            // at unrelocated linker-computed values → InvalidMemoryAccess on
            // first dereference inside drain_accounts. Port from V2's
            // src/vex_bpf2/elf.zig:979-1003 (proven byte-correct).
            const VM_RODATA_START_RELOC: u64 = 0x100000000;
            const text_v_start = text.sh_addr;
            const text_v_end = text.sh_addr + text.sh_size;

            // r75-bug-class-b-probe-2026-05-06: counters to verify handler effectiveness
            var rel_total: u32 = 0;
            var rel_type8_seen: u32 = 0;
            var rel_type8_applied_in_text: u32 = 0;
            var rel_type8_applied_out_text: u32 = 0;
            var rel_type8_skipped_zero: u32 = 0;
            var rel_type8_skipped_oob: u32 = 0;
            var rel_type8_skipped_below_base: u32 = 0;

            var ri: usize = 0;
            while (ri < rel_count) : (ri += 1) {
                rel_total += 1;
                const r_off = rel_sh.sh_offset + ri * @sizeOf(Elf64Rel);
                if (r_off + @sizeOf(Elf64Rel) > elf_data.len) break;
                const rel: *const Elf64Rel = @ptrCast(@alignCast(elf_data.ptr + r_off));
                const r_type = rel.getType();
                const r_sym = rel.getSymbol();

                if (r_type == 8) {
                    rel_type8_seen += 1;
                    // R_BPF_64_RELATIVE — rodata/text address fixup.
                    // In-text: split LDDW imm fields (low @+4, high @+12).
                    // Out-of-text: 64-bit value at r_offset gets RODATA_START added.
                    const target_vaddr = rel.r_offset;
                    if (target_vaddr < base_vaddr) {
                        rel_type8_skipped_below_base += 1;
                        continue;
                    }
                    const buf_off = target_vaddr - base_vaddr;
                    const in_text = (target_vaddr >= text_v_start and target_vaddr < text_v_end);
                    if (in_text) {
                        const lo_off = buf_off + 4;
                        const hi_off = buf_off + 12;
                        if (hi_off + 4 > combined_size) {
                            rel_type8_skipped_oob += 1;
                            continue;
                        }
                        const va_lo = std.mem.readInt(u32, combined[lo_off..][0..4], .little);
                        const va_hi = std.mem.readInt(u32, combined[hi_off..][0..4], .little);
                        var addr: u64 = (@as(u64, va_hi) << 32) | @as(u64, va_lo);
                        if (addr == 0) {
                            rel_type8_skipped_zero += 1;
                            continue;
                        }
                        if (addr < VM_RODATA_START_RELOC) addr += VM_RODATA_START_RELOC;
                        std.mem.writeInt(u32, combined[lo_off..][0..4], @truncate(addr & 0xffffffff), .little);
                        std.mem.writeInt(u32, combined[hi_off..][0..4], @truncate(addr >> 32), .little);
                        rel_type8_applied_in_text += 1;
                    } else {
                        const imm_off = buf_off + 4;
                        if (imm_off + 4 > combined_size) {
                            rel_type8_skipped_oob += 1;
                            continue;
                        }
                        if (buf_off + 8 > combined_size) {
                            rel_type8_skipped_oob += 1;
                            continue;
                        }
                        const v = std.mem.readInt(u32, combined[imm_off..][0..4], .little);
                        const addr: u64 = VM_RODATA_START_RELOC + @as(u64, v);
                        std.mem.writeInt(u64, combined[buf_off..][0..8], addr, .little);
                        rel_type8_applied_out_text += 1;
                    }
                    continue;
                }

                if (r_type != 10) continue; // R_BPF_64_32 = call_imm
                if (r_sym >= dynsym_count) continue;

                const sym_off = dynsym_sh.sh_offset + r_sym * @sizeOf(Elf64Symbol);
                if (sym_off + @sizeOf(Elf64Symbol) > elf_data.len) continue;
                const sym: *const Elf64Symbol = @ptrCast(@alignCast(elf_data.ptr + sym_off));
                const sym_name = self.getStringFromTable(elf_data, dynstr_sh.sh_offset, sym.st_name);
                if (sym_name.len == 0) continue;

                const target_vaddr = rel.r_offset;
                if (target_vaddr < base_vaddr) continue;
                const buf_off = target_vaddr - base_vaddr;
                if (buf_off + 8 > combined_size) continue;

                const is_func_in_text = (sym.st_info & 0x0f) == 2 and sym.st_value != 0 and sym.st_value >= text.sh_addr and sym.st_value < text.sh_addr + text.sh_size;

                const hash: u32 = if (is_func_in_text) blk: {
                    const target_pc = (sym.st_value - text.sh_addr) / 8;
                    const h = murmur3(sym_name);
                    function_registry.put(self.allocator, h, target_pc) catch {};
                    break :blk h;
                } else murmur3(sym_name);

                std.mem.writeInt(u32, combined[buf_off + 4 ..][0..4], hash, .little);
            }

            // r75-bug-class-b-probe-2026-05-06: log relocation pass effectiveness
            std.log.warn("[BPF-RELOC] type8_seen={d} applied_in_text={d} applied_out_text={d} skipped_zero={d} skipped_oob={d} skipped_below_base={d} total_iter={d} rel_count={d}", .{
                rel_type8_seen,         rel_type8_applied_in_text, rel_type8_applied_out_text,
                rel_type8_skipped_zero, rel_type8_skipped_oob,     rel_type8_skipped_below_base,
                rel_total,              rel_count,
            });
        }

        // Compute fd_vm_init parameters
        // text_offset  = byte offset of .text within combined buffer
        // entry_pc     = instruction index = (e_entry - text.sh_addr) / 8
        const text_offset: u64 = text.sh_addr - base_vaddr;
        const text_size: u64 = text.sh_size;
        const entry_byte: u64 = if (header.e_entry >= text.sh_addr and
            header.e_entry < text.sh_addr + text_size)
            header.e_entry - text.sh_addr
        else
            0;
        const entry_pc: u64 = entry_byte / 8;

        // Parse symbol table — populate the legacy `symbols` map (name →
        // vaddr). function_registry was init'd earlier so the relocation
        // pass could populate it; here we add STT_FUNC entries from .symtab.
        var symbols = std.StringHashMap(u64).init(self.allocator);
        errdefer symbols.deinit();

        // Always register entry — programs frequently call back to "entrypoint".
        function_registry.put(self.allocator, murmur3("entrypoint"), entry_pc) catch {};

        if (symtab_section != null and strtab_section != null) {
            const symtab = symtab_section.?;
            const strtab = strtab_section.?;
            const sym_count = symtab.sh_size / @sizeOf(Elf64Symbol);
            var idx: usize = 0;
            while (idx < sym_count) : (idx += 1) {
                const sym_off = symtab.sh_offset + idx * @sizeOf(Elf64Symbol);
                if (sym_off + @sizeOf(Elf64Symbol) > elf_data.len) break;
                const sym: *const Elf64Symbol = @ptrCast(@alignCast(elf_data.ptr + sym_off));
                const sym_name = self.getStringFromTable(elf_data, strtab.sh_offset, sym.st_name);
                if (sym_name.len == 0 or sym.st_value == 0) continue;

                // Legacy symbols map (kept for compatibility).
                const nc = self.allocator.dupe(u8, sym_name) catch continue;
                symbols.put(nc, sym.st_value) catch {
                    self.allocator.free(nc);
                };

                // Function registry: only STT_FUNC (0x02) symbols inside .text.
                const is_func = (sym.st_info & 0x0f) == 2;
                if (!is_func) continue;
                const text_vaddr = base_vaddr + text_offset;
                if (sym.st_value < text_vaddr) continue;
                if (sym.st_value >= text_vaddr + text_size) continue;
                const sym_pc = (sym.st_value - text_vaddr) / 8;
                function_registry.put(self.allocator, murmur3(sym_name), sym_pc) catch {};
            }
        }

        // r75-bug-class-b-2026-05-06: rodata vaddr port from vex_bpf2 commit
        // 21298a3. For V3 strict: base_vaddr is 0 → rodata_vaddr = VM_RODATA_START
        // (preserves current behavior). For V0/V1/V2 lenient: base_vaddr is the
        // lowest .text/.rodata sh_addr (typically 0x120 for Anchor programs) →
        // rodata_vaddr = VM_RODATA_START + base_vaddr (= 0x100000120 for HistoryJT).
        const rodata_vaddr_v: u64 = VM_RODATA_START + base_vaddr;

        return LoadedProgram{
            .rodata_combined = combined,
            .text_offset = text_offset,
            .text_size = text_size,
            .entry_pc = entry_pc,
            .sbpf_version = parseSbpfVersionFromEflags(header.e_flags),
            .rodata_vaddr = rodata_vaddr_v,
            .symbols = symbols,
            .function_registry = function_registry,
            .allocator = self.allocator,
        };
    }

    fn getSectionHeader(self: *ElfLoader, elf_data: []const u8, header: *const Elf64Header, index: u16) ?*const Elf64SectionHeader {
        _ = self;
        const offset = header.e_shoff + @as(u64, index) * header.e_shentsize;
        if (offset + @sizeOf(Elf64SectionHeader) > elf_data.len) return null;
        return @ptrCast(@alignCast(elf_data.ptr + offset));
    }

    fn getSectionOffset(self: *ElfLoader, elf_data: []const u8, header: *const Elf64Header, index: u16) ?u64 {
        const sh = self.getSectionHeader(elf_data, header, index) orelse return null;
        return sh.sh_offset;
    }

    fn getSectionName(self: *ElfLoader, elf_data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
        _ = self;
        return getStringFromTableStatic(elf_data, strtab_offset, name_offset);
    }

    fn getStringFromTable(self: *ElfLoader, elf_data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
        _ = self;
        return getStringFromTableStatic(elf_data, strtab_offset, name_offset);
    }

    fn getStringFromTableStatic(elf_data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
        const start = strtab_offset + name_offset;
        if (start >= elf_data.len) return "";

        var end = start;
        while (end < elf_data.len and elf_data[end] != 0) : (end += 1) {}

        return elf_data[start..end];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ElfLoader: basic initialization" {
    const allocator = std.testing.allocator;
    const loader = ElfLoader.init(allocator);
    _ = loader;
}

test "ElfLoader: reject invalid magic" {
    const allocator = std.testing.allocator;
    var loader = ElfLoader.init(allocator);

    const bad_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 60;
    const result = loader.load(&bad_data);
    try std.testing.expectError(ElfError.InvalidMagic, result);
}

test "ElfLoader: reject wrong class" {
    const allocator = std.testing.allocator;
    var loader = ElfLoader.init(allocator);

    // Valid magic but 32-bit class
    var bad_data = [_]u8{0} ** 64;
    bad_data[0] = 0x7f;
    bad_data[1] = 'E';
    bad_data[2] = 'L';
    bad_data[3] = 'F';
    bad_data[4] = 1; // ELFCLASS32

    const result = loader.load(&bad_data);
    try std.testing.expectError(ElfError.InvalidClass, result);
}
