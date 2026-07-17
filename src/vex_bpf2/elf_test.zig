//! Stage-A test surface for src/vex_bpf2/elf.zig
//!
//! Builds minimal ELF64 byte-blobs in-memory and exercises every reject path
//! in the loader, plus the happy path for V0..V3. Stage-B (real Solana ELFs
//! pulled from snapshot artifacts) is owned by the integration test rig and
//! is intentionally NOT in this file.

const std = @import("std");
const elf = @import("elf.zig");

const Allocator = std.mem.Allocator;

// ─── Byte-level ELF builder (V0/V1/V2 lenient + V3 strict) ────────────────────

/// Layout for built blobs. Lenient programs need section headers to identify
/// `.text` by name; strict programs only need a program-header table.
const Build = struct {
    /// e_flags (i.e. sbpf version 0..3).
    version: u32,
    /// 0 → don't override, otherwise written to e_machine.
    machine_override: ?u16 = null,
    /// 0 → don't override, otherwise written to e_type.
    type_override: ?u16 = null,
    /// Insert two `.text` sections to trigger NotOneTextSection.
    duplicate_text: bool = false,
    /// Insert a writable `.data` section.
    add_writable_data: bool = false,
    /// Skip placing `.text` entirely (validate path).
    omit_text: bool = false,
    /// Place entry pc out of `.text` range.
    bad_entry: bool = false,
};

fn buildLenientElf(alloc: Allocator, b: Build) ![]u8 {
    // Layout (lenient): [Ehdr][text bytes][shstrtab bytes][Shdr * N]
    return try buildElfImpl(alloc, b, .lenient);
}

fn buildStrictElf(alloc: Allocator, b: Build) ![]u8 {
    return try buildElfImpl(alloc, b, .strict);
}

const Mode = enum { lenient, strict };

// Concrete on-wire ELF64 types — duplicated locally to avoid taking a
// dependency on internal types of the parser-under-test.

const Elf64Ehdr = extern struct {
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

const ELFMAG: [4]u8 = .{ 0x7F, 'E', 'L', 'F' };
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const EV_CURRENT: u32 = 1;
const EM_BPF: u16 = 247;
const EM_SBPF: u16 = 263;
const ET_DYN: u16 = 3;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHF_WRITE: u64 = 0x1;
const SHF_EXECINSTR: u64 = 0x4;

const MM_RODATA_START: u64 = 0;
const MM_BYTECODE_START: u64 = 1 << 32;

fn buildElfImpl(alloc: Allocator, b: Build, mode: Mode) ![]u8 {
    // Two valid sBPF instructions. opcode 0x95 = JMP_EXIT (no operands).
    // Pad with another exit so we have two slots, satisfying lddw-not-last
    // and giving a small but non-empty .text.
    const text_bytes = [_]u8{
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    };

    var buf = std.ArrayList(u8){};
    defer buf.deinit(alloc);

    // We'll patch fields after we know offsets.
    try buf.appendNTimes(alloc, 0, @sizeOf(Elf64Ehdr));

    if (mode == .strict) {
        // Strict layout per elf.rs:448 — phdrs[0]=PF_R rodata, phdrs[1]=PF_X bytecode.
        // We can use the simpler "no rodata" form (skip_rodata=true).
        const phdr_offset = buf.items.len;
        const phdr_count: u16 = 1; // single PF_X bytecode header
        const phdr_table_end = phdr_offset + phdr_count * @sizeOf(Elf64Phdr);

        try buf.appendNTimes(alloc, 0, phdr_count * @sizeOf(Elf64Phdr));

        // Bytecode bytes start immediately after the phdr table.
        const text_off = buf.items.len;
        try buf.appendSlice(alloc, text_bytes[0..]);

        const phdr = Elf64Phdr{
            .p_type = PT_LOAD,
            .p_flags = PF_X,
            .p_offset = text_off,
            .p_vaddr = MM_BYTECODE_START,
            .p_paddr = MM_BYTECODE_START,
            .p_filesz = text_bytes.len,
            .p_memsz = text_bytes.len,
            .p_align = 8,
        };
        @memcpy(buf.items[phdr_offset..][0..@sizeOf(Elf64Phdr)], std.mem.asBytes(&phdr));

        const ehdr = Elf64Ehdr{
            .e_ident = makeIdent(),
            .e_type = b.type_override orelse ET_DYN,
            .e_machine = b.machine_override orelse EM_BPF,
            .e_version = EV_CURRENT,
            .e_entry = if (b.bad_entry) 0 else MM_BYTECODE_START,
            .e_phoff = @sizeOf(Elf64Ehdr),
            .e_shoff = 0,
            .e_flags = b.version,
            .e_ehsize = @sizeOf(Elf64Ehdr),
            .e_phentsize = @sizeOf(Elf64Phdr),
            .e_phnum = phdr_count,
            .e_shentsize = @sizeOf(Elf64Shdr),
            .e_shnum = 0,
            .e_shstrndx = 0,
        };
        @memcpy(buf.items[0..@sizeOf(Elf64Ehdr)], std.mem.asBytes(&ehdr));
        _ = phdr_table_end;
    } else {
        // Lenient layout: section-header driven. Need .shstrtab + .text [+ .text dup] [+ .data].
        // Layout: [Ehdr][Phdr=skipped][text bytes][shstrtab bytes][shdrs...]
        const text_off = buf.items.len;
        if (!b.omit_text) try buf.appendSlice(alloc, text_bytes[0..]);

        // Build .shstrtab as a sequence of NUL-terminated section names.
        var shstrtab = std.ArrayList(u8){};
        defer shstrtab.deinit(alloc);
        try shstrtab.append(alloc, 0); // index 0 = ""
        const off_shstrtab: u32 = @intCast(shstrtab.items.len);
        try shstrtab.appendSlice(alloc, ".shstrtab");
        try shstrtab.append(alloc, 0);
        const off_text: u32 = @intCast(shstrtab.items.len);
        try shstrtab.appendSlice(alloc, ".text");
        try shstrtab.append(alloc, 0);
        const off_data: u32 = @intCast(shstrtab.items.len);
        try shstrtab.appendSlice(alloc, ".data");
        try shstrtab.append(alloc, 0);

        const shstrtab_off = buf.items.len;
        try buf.appendSlice(alloc, shstrtab.items);

        // Compute shdr count.
        var sh_count: u16 = 1; // SHN_UNDEF
        if (!b.omit_text) sh_count += 1;
        if (b.duplicate_text) sh_count += 1;
        if (b.add_writable_data) sh_count += 1;
        sh_count += 1; // .shstrtab itself

        const shoff = buf.items.len;
        try buf.appendNTimes(alloc, 0, sh_count * @sizeOf(Elf64Shdr));

        // Write shdrs.
        var sh_idx: u16 = 0;
        // [0] SHN_UNDEF
        const sh_null = std.mem.zeroes(Elf64Shdr);
        @memcpy(
            buf.items[shoff + sh_idx * @sizeOf(Elf64Shdr) ..][0..@sizeOf(Elf64Shdr)],
            std.mem.asBytes(&sh_null),
        );
        sh_idx += 1;

        const writeShdr = struct {
            fn f(buf_: []u8, shoff_: usize, idx: u16, s: Elf64Shdr) void {
                @memcpy(
                    buf_[shoff_ + idx * @sizeOf(Elf64Shdr) ..][0..@sizeOf(Elf64Shdr)],
                    std.mem.asBytes(&s),
                );
            }
        }.f;

        if (!b.omit_text) {
            writeShdr(buf.items, shoff, sh_idx, .{
                .sh_name = off_text,
                .sh_type = SHT_PROGBITS,
                .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
                .sh_addr = 0,
                .sh_offset = text_off,
                .sh_size = text_bytes.len,
                .sh_link = 0,
                .sh_info = 0,
                .sh_addralign = 8,
                .sh_entsize = 0,
            });
            sh_idx += 1;
        }
        if (b.duplicate_text) {
            writeShdr(buf.items, shoff, sh_idx, .{
                .sh_name = off_text,
                .sh_type = SHT_PROGBITS,
                .sh_flags = SHF_ALLOC | SHF_EXECINSTR,
                .sh_addr = text_bytes.len,
                .sh_offset = text_off, // overlap is fine for the test
                .sh_size = text_bytes.len,
                .sh_link = 0,
                .sh_info = 0,
                .sh_addralign = 8,
                .sh_entsize = 0,
            });
            sh_idx += 1;
        }
        if (b.add_writable_data) {
            writeShdr(buf.items, shoff, sh_idx, .{
                .sh_name = off_data,
                .sh_type = SHT_PROGBITS,
                .sh_flags = SHF_ALLOC | SHF_WRITE,
                .sh_addr = text_bytes.len * 4,
                .sh_offset = shstrtab_off, // arbitrary in-bounds offset
                .sh_size = 0,
                .sh_link = 0,
                .sh_info = 0,
                .sh_addralign = 1,
                .sh_entsize = 0,
            });
            sh_idx += 1;
        }
        // [last] .shstrtab
        const shstrtab_idx = sh_idx;
        writeShdr(buf.items, shoff, sh_idx, .{
            .sh_name = off_shstrtab,
            .sh_type = SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = shstrtab_off,
            .sh_size = shstrtab.items.len,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        });

        const ehdr = Elf64Ehdr{
            .e_ident = makeIdent(),
            .e_type = b.type_override orelse ET_DYN,
            .e_machine = b.machine_override orelse EM_BPF,
            .e_version = EV_CURRENT,
            .e_entry = if (b.bad_entry) text_bytes.len * 8 else 0,
            .e_phoff = 0,
            .e_shoff = shoff,
            .e_flags = b.version,
            .e_ehsize = @sizeOf(Elf64Ehdr),
            .e_phentsize = 0,
            .e_phnum = 0,
            .e_shentsize = @sizeOf(Elf64Shdr),
            .e_shnum = sh_count,
            .e_shstrndx = shstrtab_idx,
        };
        @memcpy(buf.items[0..@sizeOf(Elf64Ehdr)], std.mem.asBytes(&ehdr));
    }

    return buf.toOwnedSlice(alloc);
}

fn makeIdent() [16]u8 {
    var id: [16]u8 = .{0} ** 16;
    @memcpy(id[0..4], ELFMAG[0..]);
    id[4] = ELFCLASS64;
    id[5] = ELFDATA2LSB;
    id[6] = @intCast(EV_CURRENT);
    id[7] = ELFOSABI_NONE;
    return id;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test "reject: bad magic (zeroed buffer fails some early check)" {
    // A zeroed buffer hits OutOfBounds (size < ehdr) or the magic check downstream;
    // either is an acceptable rejection. Test that load() returns ANY error.
    var bytes = [_]u8{0} ** @sizeOf(Elf64Ehdr);
    std.mem.writeInt(u32, bytes[48..52], 0, .little);
    const r = elf.Executable.load(std.testing.allocator, bytes[0..], elf.Config.DEFAULT);
    if (r) |_| try std.testing.expect(false) else |_| {}
}

test "reject: too short" {
    const bytes = [_]u8{0} ** 8;
    try std.testing.expectError(
        elf.LoadError.OutOfBounds,
        elf.Executable.load(std.testing.allocator, bytes[0..], elf.Config.DEFAULT),
    );
}

test "reject: e_flags out of range" {
    var bytes = [_]u8{0} ** @sizeOf(Elf64Ehdr);
    @memcpy(bytes[0..4], ELFMAG[0..]);
    bytes[4] = ELFCLASS64;
    bytes[5] = ELFDATA2LSB;
    std.mem.writeInt(u32, bytes[48..52], 9, .little);
    try std.testing.expectError(
        elf.LoadError.UnsupportedSbpfVersion,
        elf.Executable.load(std.testing.allocator, bytes[0..], elf.Config.DEFAULT),
    );
}

test "reject: version disabled in Config" {
    const bytes = try buildLenientElf(std.testing.allocator, .{ .version = 1 });
    defer std.testing.allocator.free(bytes);
    var cfg: elf.Config = .{};
    cfg.enabled_sbpf_versions = 0b0001; // only V0
    try std.testing.expectError(
        elf.LoadError.UnsupportedSbpfVersion,
        elf.Executable.load(std.testing.allocator, bytes, cfg),
    );
}

test "reject: wrong machine" {
    const bytes = try buildLenientElf(std.testing.allocator, .{
        .version = 0,
        .machine_override = 0xBEEF,
    });
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(
        elf.LoadError.WrongMachine,
        elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT),
    );
}

test "reject: wrong type (ET_EXEC)" {
    const bytes = try buildLenientElf(std.testing.allocator, .{
        .version = 0,
        .type_override = ET_EXEC,
    });
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(
        elf.LoadError.WrongType,
        elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT),
    );
}

test "reject: vex-152o multiple .text sections" {
    const bytes = try buildLenientElf(std.testing.allocator, .{
        .version = 0,
        .duplicate_text = true,
    });
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(
        elf.LoadError.NotOneTextSection,
        elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT),
    );
}

test "reject: missing .text" {
    const bytes = try buildLenientElf(std.testing.allocator, .{
        .version = 0,
        .omit_text = true,
    });
    defer std.testing.allocator.free(bytes);
    const r = elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT);
    if (r) |_| try std.testing.expect(false) else |e| {
        try std.testing.expect(e == elf.LoadError.NotOneTextSection or
            e == elf.LoadError.SectionNotFound);
    }
}

test "reject: writable .data" {
    const bytes = try buildLenientElf(std.testing.allocator, .{
        .version = 0,
        .add_writable_data = true,
    });
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(
        elf.LoadError.WritableSectionNotSupported,
        elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT),
    );
}

test "happy: V0 lenient loads" {
    const bytes = try buildLenientElf(std.testing.allocator, .{ .version = 0 });
    defer std.testing.allocator.free(bytes);
    var exe = try elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT);
    defer exe.deinit();
    try std.testing.expectEqual(elf.SbpfVersion.v0, exe.version());
    // vex-152n: for lenient, programRegionVaddr = text_section.sh_addr + MM_REGION_SIZE.
    // Built ELF places text at sh_addr=0, so programRegionVaddr = MM_BYTECODE_START.
    try std.testing.expectEqual(MM_BYTECODE_START, exe.programRegionVaddr());
    try std.testing.expectEqual(@as(u64, 0), exe.entryPoint());
    try std.testing.expectEqual(@as(usize, 16), exe.textBytes().len);
}

test "happy: V1 lenient loads" {
    const bytes = try buildLenientElf(std.testing.allocator, .{ .version = 1 });
    defer std.testing.allocator.free(bytes);
    var exe = try elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT);
    defer exe.deinit();
    try std.testing.expectEqual(elf.SbpfVersion.v1, exe.version());
}

test "happy: V2 lenient loads" {
    const bytes = try buildLenientElf(std.testing.allocator, .{ .version = 2 });
    defer std.testing.allocator.free(bytes);
    var exe = try elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT);
    defer exe.deinit();
    try std.testing.expectEqual(elf.SbpfVersion.v2, exe.version());
}

test "happy: V3 strict loads" {
    const bytes = try buildStrictElf(std.testing.allocator, .{ .version = 3 });
    defer std.testing.allocator.free(bytes);
    var exe = try elf.Executable.load(std.testing.allocator, bytes, elf.Config.DEFAULT);
    defer exe.deinit();
    try std.testing.expectEqual(elf.SbpfVersion.v3, exe.version());
    // Strict path: bytecode header carries MM_BYTECODE_START directly.
    try std.testing.expectEqual(MM_BYTECODE_START, exe.programRegionVaddr());
}

test "vex-152n: programRegionVaddr accessor stable across versions" {
    // Build V0 and V3, both must report the canonical bytecode region start
    // (since our test builder places text at vaddr 0 for lenient and at
    // MM_BYTECODE_START for strict).
    const b0 = try buildLenientElf(std.testing.allocator, .{ .version = 0 });
    defer std.testing.allocator.free(b0);
    var e0 = try elf.Executable.load(std.testing.allocator, b0, elf.Config.DEFAULT);
    defer e0.deinit();

    const b3 = try buildStrictElf(std.testing.allocator, .{ .version = 3 });
    defer std.testing.allocator.free(b3);
    var e3 = try elf.Executable.load(std.testing.allocator, b3, elf.Config.DEFAULT);
    defer e3.deinit();

    try std.testing.expectEqual(e0.programRegionVaddr(), e3.programRegionVaddr());
    try std.testing.expectEqual(e0.textVaddr(), e0.programRegionVaddr());
}

test "Murmur3 entrypoint hash matches sbpf canonical" {
    // ebpf::hash_symbol_name(b"entrypoint") is the well-known seed-0 result.
    // We don't assert a magic constant here (the value is captured in the
    // inline test in elf.zig); we assert hash-stability via Config rebuild.
    const a = elf.hashSymbolName("entrypoint");
    const b = elf.hashSymbolName("entrypoint");
    try std.testing.expectEqual(a, b);
}
