//! sBPF program loading — ELF parse, verification, function registry
//!
//! Loads a Solana ELF binary into a form the interpreter can run directly.
//! Supports EM_BPF (247) and EM_SBPF (263) machine types.
//!
//! References:
//!   sig/src/vm/executable.zig (Executable, Config, Registry, verify)
//!   sig/src/vm/elf.zig        (ELF parsing)
//!   fd_vm.h                   (fd_vm_init parameters: rodata, text_off, entry_pc)
//!   agave: sbpf/src/elf.rs, sbpf/src/verifier.rs

const std = @import("std");
const sbpf = @import("vm_sbpf.zig");
const mem = @import("vm_memory.zig");

const Version = sbpf.Version;
const Instruction = sbpf.Instruction;
const Allocator = std.mem.Allocator;

// ── ELF machine types ─────────────────────────────────────────────────────────
const EM_BPF: u16 = 247;
const EM_SBPF: u16 = 263; // Solana-specific (SIMD-0189)

// ── VM config ────────────────────────────────────────────────────────────────
// cf. sig/src/vm/executable.zig:Config
pub const Config = struct {
    /// Maximum SBPF version to accept; programs exceeding this are rejected.
    maximum_version: Version = .v0,
    /// Stack frame size in bytes (4096 for all current versions).
    stack_frame_size: u64 = sbpf.STACK_FRAME_SIZE,
    /// Heap size in bytes.
    heap_size: u64 = sbpf.HEAP_SIZE,
    /// Whether memory accesses must be aligned.
    aligned_memory_mapping: bool = true,
    /// Track instruction count against the compute meter.
    enable_instruction_meter: bool = true,
    /// Enforce strict ELF header requirements (SIMD-0189 / V3).
    stricter_elf_headers: bool = false,

    pub const DEFAULT = Config{};
};

// ── Function registry ─────────────────────────────────────────────────────────
// Stores (hash → pc) for all known functions / entrypoints.
// fd_sbpf_calldests_t / sig/src/vm/executable.zig:Registry

pub const FunctionEntry = struct {
    name: []const u8, // owned by registry
    value: u64, // instruction index (pc)
};

pub const FunctionRegistry = struct {
    entries: std.AutoHashMapUnmanaged(u32, FunctionEntry),

    pub fn init() FunctionRegistry {
        return .{ .entries = .{} };
    }

    pub fn deinit(self: *FunctionRegistry, allocator: Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| allocator.free(kv.value_ptr.name);
        self.entries.deinit(allocator);
    }

    /// Register a named function at the given PC.
    pub fn register(
        self: *FunctionRegistry,
        allocator: Allocator,
        name: []const u8,
        pc: u64,
    ) error{OutOfMemory}!void {
        const hash = murmur3(name);
        const owned = try allocator.dupe(u8, name);
        errdefer allocator.free(owned);
        try self.entries.put(allocator, hash, .{ .name = owned, .value = pc });
    }

    /// Look up by murmur3 hash (as used in call imm instructions).
    pub fn lookupKey(self: *const FunctionRegistry, key: u32) ?FunctionEntry {
        return self.entries.get(key);
    }

    /// Look up by name.
    pub fn lookupName(self: *const FunctionRegistry, name: []const u8) ?FunctionEntry {
        return self.entries.get(murmur3(name));
    }

    /// Test if a PC is a valid call target.
    /// fd_sbpf_calldests_test: O(n) linear scan; acceptable for small registries.
    pub fn isValidTarget(self: *const FunctionRegistry, pc: u64) bool {
        var it = self.entries.iterator();
        while (it.next()) |kv| if (kv.value_ptr.value == pc) return true;
        return false;
    }
};

// ── Loaded executable ─────────────────────────────────────────────────────────
// Equivalent to fd_vm_init parameters wrapped in a struct.
// sig/src/vm/executable.zig:Executable

pub const Executable = struct {
    /// Flat rodata buffer: all ALLOC ELF sections in vaddr order.
    /// Contains .text + .rodata.  Passed as "rodata" to fd_vm_init.
    rodata: []u8,
    /// instructions: byte-slice view of the .text section inside rodata.
    instructions: []align(1) const Instruction,
    /// Virtual address of the start of .text (depends on Version).
    text_vaddr: u64,
    /// Entry point as instruction index (0-based).
    entry_pc: u64,
    /// sBPF version detected from ELF flags.
    version: Version,
    /// Configuration this program was loaded with.
    config: Config,
    /// Function call destinations.
    function_registry: FunctionRegistry,
    allocator: Allocator,

    pub fn deinit(self: *Executable) void {
        self.allocator.free(self.rodata);
        self.function_registry.deinit(self.allocator);
    }
};

// ── Errors ────────────────────────────────────────────────────────────────────
pub const LoadError = error{
    InvalidMagic,
    InvalidClass,
    InvalidEncoding,
    UnsupportedMachine,
    InvalidVersion,
    NoTextSection,
    SectionOutOfBounds,
    InvalidElfData,
    InvalidSectionHeader,
    ProgramTooLarge,
    OutOfMemory,
    // Verifier errors
    NoProgram,
    DivisionByZero,
    LddwCannotBeLast,
    JumpOutOfCode,
    UnknownOpCode,
    InvalidRegister,
};

// ── ELF structures ────────────────────────────────────────────────────────────
// All matching elf.h / sig/src/vm/elf.zig ELF64 types.

const Elf64Hdr = extern struct {
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

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

// ELF flags field (e_flags) encodes sbpf version.
// sig/src/vm/elf.zig:ElfFlags  /  agave: sbpf/src/elf.rs parse_sbpf_version
const ELF_FLAG_SBPF_V1: u32 = 0x20;

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load a Solana BPF program from raw ELF bytes.
/// On success, caller owns the returned Executable and must call deinit().
///
/// Corresponds to fd_vm_init parameters (fd_vm.h).
pub fn load(
    allocator: Allocator,
    elf_data: []const u8,
    config: Config,
) LoadError!Executable {
    if (@as(u64, elf_data.len) > sbpf.MAX_FILE_SIZE) return LoadError.ProgramTooLarge;
    if (elf_data.len < @sizeOf(Elf64Hdr)) return LoadError.InvalidElfData;

    // Ensure alignment for direct struct casts.
    var aligned_buf: ?[]align(8) u8 = null;
    const data: []align(8) const u8 = if (@intFromPtr(elf_data.ptr) % 8 == 0)
        @alignCast(elf_data)
    else blk: {
        aligned_buf = allocator.alignedAlloc(u8, 8, elf_data.len) catch return LoadError.OutOfMemory;
        @memcpy(aligned_buf.?, elf_data);
        break :blk aligned_buf.?;
    };
    defer if (aligned_buf) |b| allocator.free(b);

    const hdr: *const Elf64Hdr = @ptrCast(data.ptr);

    // Magic check
    if (!std.mem.eql(u8, hdr.e_ident[0..4], "\x7fELF")) return LoadError.InvalidMagic;
    if (hdr.e_ident[4] != 2) return LoadError.InvalidClass; // ELFCLASS64
    if (hdr.e_ident[5] != 1) return LoadError.InvalidEncoding; // little-endian
    if (hdr.e_machine != EM_BPF and hdr.e_machine != EM_SBPF)
        return LoadError.UnsupportedMachine;

    // Detect version from ELF e_flags.
    // fd_vm.h / sig/src/vm/elf.zig:parseSbpfVersion
    const version: Version = blk: {
        const raw_ver = (hdr.e_flags >> 5) & 0xF; // upper nibble of flags
        break :blk if (raw_ver >= 3) .v3 else if (raw_ver >= 2) .v2 else if (raw_ver >= 1 or (hdr.e_flags & ELF_FLAG_SBPF_V1 != 0)) .v1 else .v0;
    };
    // Reject programs newer than our configured maximum.
    if (@intFromEnum(version) > @intFromEnum(config.maximum_version))
        return LoadError.InvalidVersion;

    // Get section header string table.
    if (hdr.e_shstrndx >= hdr.e_shnum) return LoadError.InvalidSectionHeader;
    const shstrtab_sh = getShdr(data, hdr, hdr.e_shstrndx) orelse return LoadError.InvalidSectionHeader;

    // Pass 1: find virtual address range of all ALLOC sections; find .text.
    var base_vaddr: u64 = std.math.maxInt(u64);
    var top_vaddr: u64 = 0;
    var text_sh: ?*const Elf64Shdr = null;
    var symtab_sh: ?*const Elf64Shdr = null;
    var strtab_sh: ?*const Elf64Shdr = null;
    {
        var i: u16 = 0;
        while (i < hdr.e_shnum) : (i += 1) {
            const sh = getShdr(data, hdr, i) orelse continue;
            const name = getStr(data, shstrtab_sh.sh_offset, sh.sh_name);
            if (sh.sh_flags & SHF_ALLOC != 0 and sh.sh_size > 0) {
                if (sh.sh_addr < base_vaddr) base_vaddr = sh.sh_addr;
                const top = sh.sh_addr +% sh.sh_size;
                if (top > top_vaddr) top_vaddr = top;
            }
            if (std.mem.eql(u8, name, ".text")) text_sh = sh;
            if (sh.sh_type == SHT_SYMTAB) symtab_sh = sh;
            if (sh.sh_type == SHT_STRTAB and !std.mem.eql(u8, name, ".shstrtab")) strtab_sh = sh;
        }
    }

    const text = text_sh orelse return LoadError.NoTextSection;
    if (base_vaddr == std.math.maxInt(u64) or top_vaddr <= base_vaddr)
        return LoadError.InvalidElfData;

    const combined_size = top_vaddr - base_vaddr;
    if (combined_size > 64 * 1024 * 1024) return LoadError.ProgramTooLarge;

    // Pass 2: build flat rodata buffer (all ALLOC sections in vaddr order).
    const rodata = allocator.alloc(u8, @intCast(combined_size)) catch return LoadError.OutOfMemory;
    errdefer allocator.free(rodata);
    @memset(rodata, 0);
    {
        var i: u16 = 0;
        while (i < hdr.e_shnum) : (i += 1) {
            const sh = getShdr(data, hdr, i) orelse continue;
            if (sh.sh_flags & SHF_ALLOC == 0 or sh.sh_size == 0) continue;
            if (sh.sh_type == SHT_NOBITS) continue; // .bss — leave zero
            const buf_off = sh.sh_addr - base_vaddr;
            const file_end = sh.sh_offset + sh.sh_size;
            if (file_end > @as(u64, data.len)) return LoadError.SectionOutOfBounds;
            if (buf_off + sh.sh_size > combined_size) return LoadError.SectionOutOfBounds;
            @memcpy(rodata[@intCast(buf_off)..@intCast(buf_off + sh.sh_size)], data[@intCast(sh.sh_offset)..@intCast(file_end)]);
        }
    }

    // Compute fd_vm_init parameters.
    const text_off = text.sh_addr - base_vaddr;
    const text_size = text.sh_size;
    const entry_byte: u64 = if (hdr.e_entry >= text.sh_addr and
        hdr.e_entry < text.sh_addr + text_size)
        hdr.e_entry - text.sh_addr
    else
        0;
    const entry_pc = entry_byte / 8;

    const text_vaddr = version.textVaddr();
    const instructions = std.mem.bytesAsSlice(Instruction, rodata[@intCast(text_off)..@intCast(text_off + text_size)]);

    // Build function registry.
    var registry = FunctionRegistry.init();
    errdefer registry.deinit(allocator);

    // Always register "entrypoint" at entry_pc.
    registry.register(allocator, "entrypoint", entry_pc) catch return LoadError.OutOfMemory;

    // Parse symbol table for additional functions.
    if (symtab_sh != null and strtab_sh != null) {
        const sym_sh = symtab_sh.?;
        const str_sh = strtab_sh.?;
        const sym_count: usize = @intCast(sym_sh.sh_size / @sizeOf(Elf64Sym));
        var idx: usize = 0;
        while (idx < sym_count) : (idx += 1) {
            const sym_off: usize = @intCast(sym_sh.sh_offset + idx * @sizeOf(Elf64Sym));
            if (sym_off + @sizeOf(Elf64Sym) > data.len) break;
            const sym: *const Elf64Sym = @ptrCast(@alignCast(data.ptr + sym_off));
            const sname = getStr(data, str_sh.sh_offset, sym.st_name);
            // Register callable functions: STT_FUNC (0x02) or entrypoint.
            const is_func = (sym.st_info & 0x0f) == 2; // STT_FUNC
            if (sname.len > 0 and sym.st_value != 0 and is_func) {
                const sym_pc = if (sym.st_value >= text.sh_addr)
                    (sym.st_value - text.sh_addr) / 8
                else
                    continue;
                registry.register(allocator, sname, sym_pc) catch {}; // ignore OOM on extras
            }
        }
    }

    var exe = Executable{
        .rodata = rodata,
        .instructions = instructions,
        .text_vaddr = text_vaddr,
        .entry_pc = entry_pc,
        .version = version,
        .config = config,
        .function_registry = registry,
        .allocator = allocator,
    };

    // Verification pass (basic — full verifier is below).
    try verify(&exe);

    return exe;
}

// ── Verifier ─────────────────────────────────────────────────────────────────
// cf. sig/src/vm/executable.zig:Executable.verify
// cf. agave: sbpf/src/verifier.rs

fn verify(exe: *const Executable) LoadError!void {
    const insns = exe.instructions;
    const ver = exe.version;
    const n = insns.len;
    if (n == 0) return LoadError.NoProgram;

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const inst = insns[i];
        const op = inst.opcode;
        const cls = op & 0x07;
        const dst: u4 = @truncate(inst.dst);
        const src: u4 = @truncate(inst.src);
        _ = src;

        // r10 is the frame pointer — writing it is illegal.
        const dst_is_r10 = dst == 10;

        switch (cls) {
            sbpf.CLS_ALU64, sbpf.CLS_ALU32 => {
                if (dst_is_r10) return LoadError.InvalidRegister;
                // lddw check: V2+ disables it (SIMD-0173).
                if (op == sbpf.OP_LDDW and ver.disableLddw())
                    return LoadError.UnknownOpCode;
                // lddw must not be the last instruction.
                if (op == sbpf.OP_LDDW) {
                    if (i + 1 >= n) return LoadError.LddwCannotBeLast;
                    i += 1; // consume the wide-load second word
                }
            },
            sbpf.CLS_LD => {
                if (op == sbpf.OP_LDDW) {
                    if (ver.disableLddw()) return LoadError.UnknownOpCode;
                    if (i + 1 >= n) return LoadError.LddwCannotBeLast;
                    if (dst_is_r10) return LoadError.InvalidRegister;
                    i += 1;
                }
            },
            sbpf.CLS_LDX, sbpf.CLS_ST, sbpf.CLS_STX => {
                if (cls == sbpf.CLS_STX or cls == sbpf.CLS_ST) {
                    // no-op check: destination base register writable
                }
            },
            sbpf.CLS_JMP, sbpf.CLS_JMP32 => {
                const jop = op & 0xf0;
                if (jop != sbpf.JMP_CALL and jop != sbpf.JMP_EXIT) {
                    // Conditional / unconditional branch — check target stays in text.
                    const off: i64 = inst.off;
                    const target: i64 = @as(i64, @intCast(i + 1)) + off;
                    if (target < 0 or @as(u64, @intCast(target)) >= n)
                        return LoadError.JumpOutOfCode;
                }
            },
            else => {},
        }
    }
}

// ── ELF helpers ──────────────────────────────────────────────────────────────

fn getShdr(data: []align(8) const u8, hdr: *const Elf64Hdr, idx: u16) ?*const Elf64Shdr {
    const off: u64 = hdr.e_shoff + @as(u64, idx) * hdr.e_shentsize;
    if (off + @sizeOf(Elf64Shdr) > @as(u64, data.len)) return null;
    return @ptrCast(@alignCast(data.ptr + @as(usize, @intCast(off))));
}

fn getStr(data: []const u8, strtab_off: u64, name_off: u32) []const u8 {
    const start: u64 = strtab_off + name_off;
    if (start >= @as(u64, data.len)) return "";
    var end: usize = @intCast(start);
    while (end < data.len and data[end] != 0) end += 1;
    return data[@intCast(start)..end];
}

// ── Murmur3_32 hash (syscall name → ID) ──────────────────────────────────────
// cf. sig/src/vm/syscalls/lib.zig:Syscall.Registry  /  std.hash.Murmur3_32
pub fn murmur3(key: []const u8) u32 {
    return std.hash.Murmur3_32.hashWithSeed(key, 0);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "murmur3: known syscall IDs" {
    // Verified against Agave rbpf
    try std.testing.expectEqual(@as(u32, 0x207559bd), murmur3("sol_log_"));
    try std.testing.expectEqual(@as(u32, 0x11f49d86), murmur3("sol_sha256"));
    try std.testing.expectEqual(@as(u32, 0xd7449092), murmur3("sol_invoke_signed_rust"));
    try std.testing.expectEqual(@as(u32, 0x83f00e8f), murmur3("sol_alloc_free_"));
}

test "load: reject bad magic" {
    const bad = [_]u8{0} ** 64;
    const err = load(std.testing.allocator, &bad, Config.DEFAULT);
    try std.testing.expectError(LoadError.InvalidMagic, err);
}
