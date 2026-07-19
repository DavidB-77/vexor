//! sBPF version detection for F8i dispatch routing.
//!
//! V1 ElfLoader does NOT support SBPFv3 (e_machine=263 / e_flags=3). Under
//! `--bpf-stack=v1|shadow`, V1 silently swallows V3 dispatches → produces 0
//! mutations → HistoryJT/ATokenG/Jito/Router PDAs freeze post-snapshot →
//! continuous bank_hash divergence (multi-week blocker confirmed
//! via byte-diff vs oracle-node).
//!
//! F8i: replay_stage routes V3 ELFs through
//! the V2 producer regardless of `--bpf-stack` flag. V0/V1/V2 ELFs continue
//! to honor the flag (V1 default) since V1 handles them correctly.
//!
//! This file holds the lightweight version sniff (e_flags read at byte 48,
//! no full Executable load) plus a program-id → version resolver that
//! follows BPF Loader Upgradeable indirection (program account → programdata
//! account → ELF bytes), mirroring replay_stage.zig:2906-2921.

const std = @import("std");
const core = @import("core");
const accounts_mod = @import("vex_store").accounts;
const elf_mod = @import("vex_bpf2").elf;

pub const SbpfVersion = elf_mod.SbpfVersion;

/// BPF Loader Upgradeable program-id (well-known constant; mirrors the
/// definition used at replay_stage.zig dispatch site). Inlined here to avoid
/// a dependency on the bpf_loader bytes module's import surface.
const BPF_LOADER_UPGRADEABLE: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
    0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
    0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
};

/// Read sBPF version from raw ELF bytes by sniffing `e_flags` at byte 48.
/// Mirrors the version-extraction logic at vex_bpf2/elf.zig:484-495 but
/// without invoking the full ELF parser (which would allocate, walk
/// program headers, and validate).
///
/// Returns null on:
///   - bytes shorter than e_flags + sizeof(u32) (= 52)
///   - e_flags value outside {0, 1, 2, 3}
/// Caller treats null as "not a recognized sBPF ELF; fall back to legacy".
pub fn elfSbpfVersion(executable_bytes: []const u8) ?SbpfVersion {
    const E_FLAGS_OFFSET: usize = 48;
    if (executable_bytes.len < E_FLAGS_OFFSET + 4) return null;
    const e_flags = std.mem.readInt(
        u32,
        executable_bytes[E_FLAGS_OFFSET..][0..4],
        .little,
    );
    return switch (e_flags) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => null,
    };
}

/// Resolve a program-id to its sBPF version by walking AccountsDb:
///   1. Look up program account
///   2. If owner is BPF Loader Upgradeable + state == ProgramData (= 2):
///      follow the programdata pubkey, ELF bytes start at byte 45
///   3. Else: ELF bytes are the program account's data directly
///   4. Sniff version from those bytes
///
/// Returns null on any lookup miss or unrecognized e_flags. Native programs
/// (Vote, Stake, System, ALT, ComputeBudget, etc.) return null because their
/// account "data" isn't an ELF.
pub fn resolveProgramSbpfVersion(
    program_id: *const [32]u8,
    db: *accounts_mod.AccountsDb,
    slot: core.Slot,
    ancestors: []const core.Slot,
) ?SbpfVersion {
    const program_pk = core.Pubkey{ .data = program_id.* };
    const prog_acct = db.getAccountInSlot(&program_pk, slot, ancestors) orelse return null;

    // BPF Loader Upgradeable indirection (mirrors replay_stage.zig:2906-2921).
    if (std.mem.eql(u8, &prog_acct.owner.data, &BPF_LOADER_UPGRADEABLE) and
        prog_acct.data.len >= 36)
    {
        const state = std.mem.readInt(u32, prog_acct.data[0..4], .little);
        if (state == 2) {
            var pd_key = core.Pubkey{ .data = undefined };
            @memcpy(&pd_key.data, prog_acct.data[4..36]);
            if (db.getAccountInSlot(&pd_key, slot, ancestors)) |pd_acct| {
                if (pd_acct.data.len >= 45) {
                    return elfSbpfVersion(pd_acct.data[45..]);
                }
            }
            return null;
        }
    }
    return elfSbpfVersion(prog_acct.data);
}

// ─── Tests ────────────────────────────────────────────────────────────────

test "elfSbpfVersion: empty bytes → null" {
    try std.testing.expectEqual(@as(?SbpfVersion, null), elfSbpfVersion(&[_]u8{}));
}

test "elfSbpfVersion: short bytes (< 52) → null" {
    try std.testing.expectEqual(@as(?SbpfVersion, null), elfSbpfVersion(&[_]u8{0} ** 51));
}

test "elfSbpfVersion: e_flags=0 → .v0" {
    var buf: [52]u8 = std.mem.zeroes([52]u8);
    try std.testing.expectEqual(@as(?SbpfVersion, .v0), elfSbpfVersion(&buf));
}

test "elfSbpfVersion: e_flags=1 → .v1" {
    var buf: [52]u8 = std.mem.zeroes([52]u8);
    std.mem.writeInt(u32, buf[48..52], 1, .little);
    try std.testing.expectEqual(@as(?SbpfVersion, .v1), elfSbpfVersion(&buf));
}

test "elfSbpfVersion: e_flags=2 → .v2" {
    var buf: [52]u8 = std.mem.zeroes([52]u8);
    std.mem.writeInt(u32, buf[48..52], 2, .little);
    try std.testing.expectEqual(@as(?SbpfVersion, .v2), elfSbpfVersion(&buf));
}

test "elfSbpfVersion: e_flags=3 → .v3 (HistoryJT class)" {
    var buf: [52]u8 = std.mem.zeroes([52]u8);
    std.mem.writeInt(u32, buf[48..52], 3, .little);
    try std.testing.expectEqual(@as(?SbpfVersion, .v3), elfSbpfVersion(&buf));
}

test "elfSbpfVersion: e_flags=99 → null" {
    var buf: [52]u8 = std.mem.zeroes([52]u8);
    std.mem.writeInt(u32, buf[48..52], 99, .little);
    try std.testing.expectEqual(@as(?SbpfVersion, null), elfSbpfVersion(&buf));
}
