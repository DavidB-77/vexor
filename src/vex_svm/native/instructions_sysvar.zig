//! Per-tx Sysvar1nstructions blob construction.
//!
//! Agave canonical: `solana-instructions-sysvar-3.0.0/src/lib.rs:69-141`
//!   pub fn construct_instructions_data(instructions: &[BorrowedInstruction]) -> Vec<u8> {
//!       let mut data = serialize_instructions(instructions);
//!       data.resize(data.len() + 2, 0); // current_instruction_index trailer
//!       data
//!   }
//!
//! Vexor port: byte-exact replica of Agave's layout. Used by the V2 BPF
//! account-snapshot builder so when an instruction in the tx references
//! `Sysvar1nstructions1111111111111111111111111`, the BPF program sees the
//! transaction's own instruction list serialized in this format. Without
//! this, Anchor programs that call `load_instruction_at_checked` (e.g.
//! HistoryJT::CopyGossipContactInfo for Ed25519 precompile readback) read
//! empty/stale bytes and abort, dropping their PDA writes.
//!
//! Per-IX update: before each BPF dispatch, `storeCurrentIndex` updates the
//! trailing u16 to the current ix index (Agave: `store_current_index_checked`
//! at `solana-instructions-sysvar-3.0.0/src/lib.rs:176-186`).

const std = @import("std");

/// Pubkey of the instructions sysvar account: `Sysvar1nstructions1111111111111111111111111`
/// Bytes verified against Agave canonical `solana_sdk_ids::sysvar::instructions::ID`.
pub const INSTRUCTIONS_SYSVAR_ID: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66,
    0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
    0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5,
    0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
};

const FLAG_IS_SIGNER: u8 = 0b0000_0001;
const FLAG_IS_WRITABLE: u8 = 0b0000_0010;

/// Information needed to serialize one instruction. The caller fills this
/// once per instruction; we don't hold pointers to the wire ParsedTx so we
/// can inline the per-account flags-as-u8 step here without leaking caller
/// internals.
pub const InstructionInput = struct {
    program_id: *const [32]u8,
    /// One entry per account referenced by this instruction. Order = the order
    /// the BPF program will see in account_indices.
    accounts: []const AccountFlag,
    data: []const u8,
};

/// Per-account meta packed into the sysvar blob. `is_signer` / `is_writable`
/// are computed by the caller from the parsed-tx writability table — Vexor's
/// `ParsedTx.isWritable` + the `index < num_required_sigs` rule.
pub const AccountFlag = struct {
    pubkey: *const [32]u8,
    is_signer: bool,
    is_writable: bool,
};

/// Serialize the instruction list into the per-tx sysvar blob and append the
/// 2-byte `current_instruction_index` trailer (initialized to zero; update via
/// `storeCurrentIndex` before each BPF dispatch).
///
/// Caller owns the returned slice and frees with the same allocator.
///
/// Layout (Agave `solana-instructions-sysvar-3.0.0/src/lib.rs:85-108`):
///   [0..2]                  num_instructions: u16 LE
///   [2..2+2*N]              instruction_offsets: [u16 LE; N]
///   per IX (at offset[i]):
///     [+0..+2]              num_accounts: u16 LE
///     [+2..]                A × { flags: u8, pubkey: [32]u8 }     // 33 bytes each
///     [...]                 program_id: [32]u8
///     [...]                 data_len: u16 LE
///     [...]                 data: [u8; data_len]
///   tail:
///     [len-2..len]          current_instruction_index: u16 LE
pub fn constructInstructionsData(
    alloc: std.mem.Allocator,
    instructions: []const InstructionInput,
) ![]u8 {
    // Pre-compute the exact size to avoid reallocations.
    var total: usize = 2 + 2 * instructions.len + 2; // header + offset table + trailer
    for (instructions) |ix| {
        total += 2 + 33 * ix.accounts.len + 32 + 2 + ix.data.len;
    }

    const buf = try alloc.alloc(u8, total);
    @memset(buf, 0); // zero everything; trailer stays 0 until storeCurrentIndex runs

    // num_instructions
    std.mem.writeInt(u16, buf[0..2], @intCast(instructions.len), .little);

    // Cursor begins after header (2) + offset table (2*N).
    var pos: usize = 2 + 2 * instructions.len;

    for (instructions, 0..) |ix, i| {
        // Record this IX's start offset in the offset table.
        const offset_slot: usize = 2 + 2 * i;
        std.mem.writeInt(u16, buf[offset_slot..][0..2], @intCast(pos), .little);

        // num_accounts
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ix.accounts.len), .little);
        pos += 2;

        // per-account: flags + pubkey
        for (ix.accounts) |acc| {
            var flags: u8 = 0;
            if (acc.is_signer) flags |= FLAG_IS_SIGNER;
            if (acc.is_writable) flags |= FLAG_IS_WRITABLE;
            buf[pos] = flags;
            pos += 1;
            @memcpy(buf[pos..][0..32], acc.pubkey);
            pos += 32;
        }

        // program_id
        @memcpy(buf[pos..][0..32], ix.program_id);
        pos += 32;

        // data_len + data
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ix.data.len), .little);
        pos += 2;
        @memcpy(buf[pos..][0..ix.data.len], ix.data);
        pos += ix.data.len;
    }

    std.debug.assert(pos + 2 == total); // sanity: only the 2-byte trailer remains

    return buf;
}

/// Update the trailing `current_instruction_index` u16. Agave canonical
/// `store_current_index_checked` at lib.rs:176-186. Caller must invoke once
/// per BPF dispatch with the index of the instruction about to execute.
pub fn storeCurrentIndex(data: []u8, instruction_index: u16) void {
    if (data.len < 2) return;
    const last = data.len - 2;
    std.mem.writeInt(u16, data[last..][0..2], instruction_index, .little);
}

// ─────────────────────────────────────────────────────────────────────────
// Tests — boot-time KAT for byte-exact parity with Agave canonical.
// Reference: Agave's `cargo test -p solana-instructions-sysvar test_serialize_instructions`
// produces the same bytes for the same inputs.
// ─────────────────────────────────────────────────────────────────────────

test "construct_instructions_data: 2 IXs, no accounts" {
    const t = std.testing;

    const pid0 = [_]u8{1} ++ [_]u8{0} ** 31;
    const pid1 = [_]u8{2} ++ [_]u8{0} ** 31;
    const data0 = [_]u8{0xAB};
    const data1 = [_]u8{0xCD};

    const ixs = [_]InstructionInput{
        .{ .program_id = &pid0, .accounts = &[_]AccountFlag{}, .data = &data0 },
        .{ .program_id = &pid1, .accounts = &[_]AccountFlag{}, .data = &data1 },
    };

    const blob = try constructInstructionsData(t.allocator, &ixs);
    defer t.allocator.free(blob);

    // Header: num_instructions=2, offsets=[6, 43] (each ix = 2 + 0 + 32 + 2 + 1 = 37)
    try t.expectEqual(@as(u16, 2), std.mem.readInt(u16, blob[0..2], .little));
    try t.expectEqual(@as(u16, 6), std.mem.readInt(u16, blob[2..4], .little));
    try t.expectEqual(@as(u16, 6 + 37), std.mem.readInt(u16, blob[4..6], .little));

    // IX0 at offset 6
    try t.expectEqual(@as(u16, 0), std.mem.readInt(u16, blob[6..8], .little));
    try t.expectEqualSlices(u8, &pid0, blob[8..40]);
    try t.expectEqual(@as(u16, 1), std.mem.readInt(u16, blob[40..42], .little));
    try t.expectEqual(@as(u8, 0xAB), blob[42]);

    // IX1 at offset 43
    try t.expectEqual(@as(u16, 0), std.mem.readInt(u16, blob[43..45], .little));
    try t.expectEqualSlices(u8, &pid1, blob[45..77]);
    try t.expectEqual(@as(u16, 1), std.mem.readInt(u16, blob[77..79], .little));
    try t.expectEqual(@as(u8, 0xCD), blob[79]);

    // Trailer: current_instruction_index initialized to 0
    // Total = header(6) + ix0(37) + ix1(37) + trailer(2) = 82
    const tlen = blob.len;
    try t.expectEqual(@as(u16, 0), std.mem.readInt(u16, blob[tlen - 2 ..][0..2], .little));
    try t.expectEqual(@as(usize, 82), tlen);

    // storeCurrentIndex round-trip
    storeCurrentIndex(blob, 1);
    try t.expectEqual(@as(u16, 1), std.mem.readInt(u16, blob[tlen - 2 ..][0..2], .little));
}

test "construct_instructions_data: 1 IX with 2 accounts" {
    const t = std.testing;

    const pid = [_]u8{0xAA} ++ [_]u8{0} ** 31;
    const ak0 = [_]u8{0x11} ++ [_]u8{0} ** 31;
    const ak1 = [_]u8{0x22} ++ [_]u8{0} ** 31;
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    const accs = [_]AccountFlag{
        .{ .pubkey = &ak0, .is_signer = true, .is_writable = true },
        .{ .pubkey = &ak1, .is_signer = false, .is_writable = false },
    };
    const ixs = [_]InstructionInput{
        .{ .program_id = &pid, .accounts = &accs, .data = &data },
    };

    const blob = try constructInstructionsData(t.allocator, &ixs);
    defer t.allocator.free(blob);

    // num_instructions=1
    try t.expectEqual(@as(u16, 1), std.mem.readInt(u16, blob[0..2], .little));
    // offset[0]=4
    try t.expectEqual(@as(u16, 4), std.mem.readInt(u16, blob[2..4], .little));
    // num_accounts=2
    try t.expectEqual(@as(u16, 2), std.mem.readInt(u16, blob[4..6], .little));
    // account 0: flags=0b11 (signer + writable), then pubkey
    try t.expectEqual(@as(u8, 0b11), blob[6]);
    try t.expectEqualSlices(u8, &ak0, blob[7..39]);
    // account 1: flags=0
    try t.expectEqual(@as(u8, 0), blob[39]);
    try t.expectEqualSlices(u8, &ak1, blob[40..72]);
    // program_id
    try t.expectEqualSlices(u8, &pid, blob[72..104]);
    // data_len=4 + data
    try t.expectEqual(@as(u16, 4), std.mem.readInt(u16, blob[104..106], .little));
    try t.expectEqualSlices(u8, &data, blob[106..110]);
    // trailer
    try t.expectEqual(@as(usize, 112), blob.len);
}
