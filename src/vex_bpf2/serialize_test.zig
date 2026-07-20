//! M5 test suite: byte-level fixtures + edge cases for `serialize.zig`.
//!
//! Two layers of validation:
//!
//!  1. **18 FD golden fixtures (aligned, non-DM):** the same inputs that the
//!     existing `src/vex_bpf/serialise_fixtures_test.zig` runs against
//!     `sbpf_executor.serialise()` are fed through
//!     `serializeParametersAligned`, and the produced byte buffer is compared
//!     against the base64-decoded `expected_b64` from each fixture. The
//!     existing test continues to validate the oracle (sbpf_executor); this
//!     test validates the rebuild against the same goldens directly.
//!
//!  2. **Edge cases (hand-rolled):** dup-account variants, MAX_REALLOC
//!     trailing slack, alignment edge cases (data_len mod 8 in {0,1,7,8,9}),
//!     sentinel byte values (0x00, 0xFF), 0-account and 0-data-byte cases,
//!     SerializeConfig.NotImplemented gate.
//!
//! Run with: `zig build test-vex-bpf2-serialize`

const std = @import("std");
const ser = @import("serialize.zig");
const fix = @import("serialize_fixtures_data.zig");

// ─────────────────────────────────────────────────────────────────────────────
// 1. FIXTURE PARITY: 18 FD goldens (aligned, non-DM)
// ─────────────────────────────────────────────────────────────────────────────

test "M5 fixture parity: 18 aligned non-DM FD goldens, byte-identical" {
    const alloc = std.testing.allocator;
    const B64 = std.base64.standard.Decoder;

    for (&fix.fixtures) |*fx| {
        // Build AccountInput slice ordered by instruction accounts. This
        // mirrors how the existing executor test reorders tx_accounts via
        // the ix_accounts indirection — matches Agave's serialize_parameters
        // input shape (one entry per instruction-account, deduped externally).
        var entries = try std.ArrayListUnmanaged(ser.AccountInput).initCapacity(
            alloc,
            fx.ix_accounts.len,
        );
        defer entries.deinit(alloc);
        for (fx.ix_accounts) |ixa| {
            const ta = &fx.tx_accounts[ixa.idx];
            entries.appendAssumeCapacity(.{
                .pubkey = ta.pubkey,
                .owner = ta.owner,
                .lamports = ta.lamports,
                .data = ta.data,
                .executable = ta.executable,
                .rent_epoch = ta.rent_epoch,
                .is_signer = ixa.is_signer,
                .is_writable = ixa.is_writable,
            });
        }

        // Decode expected golden buffer.
        const exp_len = try B64.calcSizeForSlice(fx.expected_b64);
        const exp = try alloc.alloc(u8, exp_len);
        defer alloc.free(exp);
        try B64.decode(exp, fx.expected_b64);

        // Run M5.
        const result = try ser.serializeParametersAligned(
            alloc,
            fx.program_id,
            fx.ix_data,
            entries.items,
            .{}, // testnet defaults: all SIMD gates OFF
        );
        defer alloc.free(result.bytes);
        defer alloc.free(result.account_layouts);

        // Byte-diff vs golden.
        if (!std.mem.eql(u8, result.bytes, exp)) {
            var first: usize = 0;
            while (first < result.bytes.len and first < exp.len and
                result.bytes[first] == exp[first]) : (first += 1)
            {}
            const lo = if (first >= 8) first - 8 else 0;
            const ghi = @min(first + 16, result.bytes.len);
            const ehi = @min(first + 16, exp.len);
            std.log.debug(
                "\n[FAIL] {s}: len got={d} exp={d} first_diff={d}\n  got[{d}..{d}]={x}\n  exp[{d}..{d}]={x}\n",
                .{
                    fx.name, result.bytes.len, exp.len,               first,
                    lo,      ghi,              result.bytes[lo..ghi], lo,
                    ehi,     exp[lo..ehi],
                },
            );
            return error.FixtureMismatch;
        }

        // ix_data vaddr matches SIMD-0321 expectation.
        const got_vaddr = ser.INPUT_START + @as(u64, @intCast(result.instruction_data_offset));
        if (got_vaddr != fx.expected_vaddr) {
            std.log.debug(
                "\n[FAIL] {s}: ix_data_vaddr got=0x{x} exp=0x{x}\n",
                .{ fx.name, got_vaddr, fx.expected_vaddr },
            );
            return error.IxDataVaddrMismatch;
        }

        // Per-account layout sanity: vaddr.host_offset round-trip.
        for (result.account_layouts, 0..) |layout, i| {
            // Non-dup layouts must have key/owner/lamports/data vaddr aligned
            // with their host offsets.
            if (!layout.is_duplicate) {
                std.debug.assert(layout.vm_lamports_addr ==
                    ser.INPUT_START + layout.host_lamports_offset);
                std.debug.assert(layout.vm_owner_addr ==
                    ser.INPUT_START + layout.host_owner_offset);
                std.debug.assert(layout.vm_data_addr ==
                    ser.INPUT_START + layout.host_data_offset);
            }
            _ = i;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. EDGE CASES (hand-rolled)
// ─────────────────────────────────────────────────────────────────────────────

const ZERO_KEY: [32]u8 = @splat(0);
const FF_KEY: [32]u8 = @splat(0xFF);

fn mkAccount(
    pubkey: [32]u8,
    owner: [32]u8,
    data: []const u8,
    is_writable: bool,
) ser.AccountInput {
    return .{
        .pubkey = pubkey,
        .owner = owner,
        .lamports = 1234,
        .data = data,
        .executable = false,
        .rent_epoch = 0,
        .is_signer = false,
        .is_writable = is_writable,
    };
}

test "M5 edge: zero accounts, zero ix data" {
    const alloc = std.testing.allocator;
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &.{},
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    // Layout: u64 acct count (0) + u64 ix_dlen (0) + 32 program_id = 48 bytes
    try std.testing.expectEqual(@as(usize, 48), r.bytes.len);
    try std.testing.expectEqual(@as(usize, 0), r.account_layouts.len);
    // first 8 bytes = 0 (account count)
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, r.bytes[0..8], .little));
    // next 8 = 0 (ix dlen)
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, r.bytes[8..16], .little));
    // program_id at bytes 16..48
    try std.testing.expectEqualSlices(u8, &ZERO_KEY, r.bytes[16..48]);
}

test "M5 edge: single account with empty data has correct trailing slack" {
    const alloc = std.testing.allocator;
    const accts = [_]ser.AccountInput{
        mkAccount(ZERO_KEY, FF_KEY, &.{}, true),
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    // Per-account size = 1 + 1+1+1+4 + 32+32 + 8+8 + 0 + (10240 + 0) + 8 = 10336
    // (data_len=0 so align_pad=0; MAX_REALLOC=10240)
    // Plus 8 (count) + 8 (ix_dlen) + 32 (prog_id) = 48
    try std.testing.expectEqual(@as(usize, 10336 + 48), r.bytes.len);

    // First byte after count must be NON_DUP_MARKER (0xFF).
    try std.testing.expectEqual(@as(u8, 0xFF), r.bytes[8]);
    try std.testing.expectEqual(@as(u8, 0), r.bytes[9]); // is_signer
    try std.testing.expectEqual(@as(u8, 1), r.bytes[10]); // is_writable
    try std.testing.expectEqual(@as(u8, 0), r.bytes[11]); // executable
    // u32 zero-pad at bytes 12..16
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, r.bytes[12..16], .little));
    // rent_epoch at end of account block = u64::MAX
    const rent_off = 8 + 1 + 7 + 32 + 32 + 8 + 8 + 0 + ser.MAX_REALLOC;
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), std.mem.readInt(u64, r.bytes[rent_off..][0..8], .little));
}

test "M5 edge: alignment pad varies with data_len mod 8" {
    const alloc = std.testing.allocator;

    // For each data_len in {0,1,7,8,9}, total size delta = data_len + pad
    // pad = (8 - len%8) % 8 → 0,7,1,0,7
    const cases = [_]struct { dlen: usize, exp_pad: usize }{
        .{ .dlen = 0, .exp_pad = 0 },
        .{ .dlen = 1, .exp_pad = 7 },
        .{ .dlen = 7, .exp_pad = 1 },
        .{ .dlen = 8, .exp_pad = 0 },
        .{ .dlen = 9, .exp_pad = 7 },
        .{ .dlen = 15, .exp_pad = 1 },
        .{ .dlen = 16, .exp_pad = 0 },
    };

    for (cases) |c| {
        try std.testing.expectEqual(c.exp_pad, ser.alignPadForLen(c.dlen));

        const data = try alloc.alloc(u8, c.dlen);
        defer alloc.free(data);
        @memset(data, 0xAB);

        const accts = [_]ser.AccountInput{
            mkAccount(ZERO_KEY, FF_KEY, data, true),
        };
        const r = try ser.serializeParametersAligned(
            alloc,
            ZERO_KEY,
            &.{},
            &accts,
            .{},
        );
        defer alloc.free(r.bytes);
        defer alloc.free(r.account_layouts);

        // Confirm the per-account block size matches accountSize().
        const expected_block = ser.accountSize(c.dlen);
        // Total = 8 + 1 dup-marker (already inside per_acct? — no, see math)
        // Layout: 8(count) + [1 dup + accountSize_body] + 8(ix dlen) + 32(prog_id)
        // Our accountSize() returns the body size; the 1-byte dup marker is
        // ALSO a body byte already counted, so total = 8 + accountSize + 8 + 32.
        const total: usize = 8 + @as(usize, @intCast(expected_block)) + 8 + 32;
        try std.testing.expectEqual(total, r.bytes.len);

        // Padded zeros sit between data + MAX_REALLOC and rent_epoch.
        // Find the rent_epoch offset and confirm the 8 bytes before it look
        // like the alignment pad (zeros only — interior of MAX_REALLOC slack).
        const rent_off = r.bytes.len - 8 - 8 - 32;
        // Rent must be u64::MAX.
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), std.mem.readInt(u64, r.bytes[rent_off..][0..8], .little));
        // The realloc slack region (10240 + pad bytes) must all be zero.
        const data_end_host = r.account_layouts[0].host_data_offset + c.dlen;
        for (r.bytes[data_end_host .. data_end_host + ser.MAX_REALLOC + c.exp_pad]) |b| {
            try std.testing.expectEqual(@as(u8, 0), b);
        }
    }
}

test "M5 edge: duplicate account collapses to 1+7 zero pad" {
    const alloc = std.testing.allocator;
    const data1 = [_]u8{ 0x11, 0x22, 0x33 };
    const accts = [_]ser.AccountInput{
        mkAccount(ZERO_KEY, FF_KEY, &data1, true),
        mkAccount(ZERO_KEY, FF_KEY, &data1, true), // dup of [0]
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    // First account body: 1 (NON_DUP) + accountSize(3)body-minus-dup = ...
    // Actually accountSize() includes everything from is_signer onward, NOT
    // the leading dup-marker byte. So per-account contribution =
    // 1 (NON_DUP) + (accountSize - 1).
    // For the DUP slot: 1 (position) + 7 zero pad = 8 bytes total.
    // Total size = 8 (count) + accountSize(3) + 8 (dup) + 8 (ix dlen) + 32.

    const dup_slot_off = 8 + @as(usize, @intCast(ser.accountSize(3)));
    try std.testing.expectEqual(@as(u8, 0), r.bytes[dup_slot_off]); // pos = 0
    for (r.bytes[dup_slot_off + 1 .. dup_slot_off + 8]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }

    // Layout for the dup slot must mirror the original's vaddrs but be flagged.
    try std.testing.expect(!r.account_layouts[0].is_duplicate);
    try std.testing.expect(r.account_layouts[1].is_duplicate);
    try std.testing.expectEqual(
        r.account_layouts[0].vm_data_addr,
        r.account_layouts[1].vm_data_addr,
    );
}

test "M5 edge: dup of 2nd account (between)" {
    const alloc = std.testing.allocator;
    const k0: [32]u8 = @splat(0x10);
    const k1: [32]u8 = @splat(0x20);
    const accts = [_]ser.AccountInput{
        mkAccount(k0, FF_KEY, "aa", true),
        mkAccount(k1, FF_KEY, "bb", true),
        mkAccount(k1, FF_KEY, "bb", true), // dup of [1]
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    try std.testing.expect(!r.account_layouts[0].is_duplicate);
    try std.testing.expect(!r.account_layouts[1].is_duplicate);
    try std.testing.expect(r.account_layouts[2].is_duplicate);
    // Dup slot's position byte must equal the index of the EARLIER occurrence.
    const dup_off = 8 + @as(usize, @intCast(ser.accountSize(2))) + @as(usize, @intCast(ser.accountSize(2)));
    try std.testing.expectEqual(@as(u8, 1), r.bytes[dup_off]);
}

test "M5 edge: sentinel data values 0x00 and 0xFF survive byte-for-byte" {
    const alloc = std.testing.allocator;
    var data: [17]u8 = undefined;
    @memset(&data, 0x00);
    data[0] = 0xFF;
    data[16] = 0xFF;

    const accts = [_]ser.AccountInput{
        mkAccount(ZERO_KEY, FF_KEY, &data, true),
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    const data_off = r.account_layouts[0].host_data_offset;
    try std.testing.expectEqualSlices(u8, &data, r.bytes[data_off .. data_off + 17]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. SIMD GATE GUARDS
// ─────────────────────────────────────────────────────────────────────────────

test "PR-3 vasa-on: serializer emits per-account regions + meta entries" {
    const alloc = std.testing.allocator;
    // Two accounts: one writable, one RO. The serializer must emit:
    //   metadata-region(writable) + data-region(account[0].is_writable) +
    //   metadata-region(writable) + data-region(account[1].is_writable) +
    //   trailing-region(writable).
    const accts = [_]ser.AccountInput{
        .{
            .pubkey = .{1} ** 32,
            .owner = .{2} ** 32,
            .lamports = 100,
            .data = "hello, vasa!",
            .executable = false,
            .rent_epoch = 0,
            .is_signer = true,
            .is_writable = true,
        },
        .{
            .pubkey = .{3} ** 32,
            .owner = .{4} ** 32,
            .lamports = 200,
            .data = "ro acct",
            .executable = false,
            .rent_epoch = 0,
            .is_signer = false,
            .is_writable = false,
        },
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{ 0xAA, 0xBB },
        &accts,
        .{ .virtual_address_space_adjustments = true },
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);
    defer alloc.free(r.input_regions);
    defer alloc.free(r.acc_region_metas);

    // 2 regions per account + 1 trailing = 5 regions total.
    try std.testing.expectEqual(@as(usize, 5), r.input_regions.len);
    try std.testing.expectEqual(@as(usize, 2), r.acc_region_metas.len);

    // Region 0: account[0] metadata — writable.
    try std.testing.expect(r.input_regions[0].is_writable);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), r.input_regions[0].acc_region_meta_idx);

    // Region 1: account[0] data — writable because is_writable=true.
    try std.testing.expect(r.input_regions[1].is_writable);
    try std.testing.expectEqual(@as(u64, 0), r.input_regions[1].acc_region_meta_idx);

    // Region 2: account[1] metadata — writable.
    try std.testing.expect(r.input_regions[2].is_writable);

    // Region 3: account[1] data — RO because is_writable=false.
    try std.testing.expect(!r.input_regions[3].is_writable);
    try std.testing.expectEqual(@as(u64, 1), r.input_regions[3].acc_region_meta_idx);

    // Trailing region (rent_epoch + ix_data + program_id) — writable.
    try std.testing.expect(r.input_regions[4].is_writable);
}

test "PR-3 vasa-on: data region's address_space_reserved is exactly dlen + MAX_PERMITTED_DATA_INCREASE (no align pad)" {
    // Regression guard for the byte-boundary fix. Firedancer's address_space_reserved
    // for a data region = sat_add(dlen, MAX_PERMITTED_DATA_INCREASE). The align_pad
    // lives OUTSIDE this region in the next metadata block. Vexor must mirror or
    // the next account's metadata bytes get clobbered on vmap.
    const alloc = std.testing.allocator;
    const data = "x" ** 13; // dlen=13 → align pad = 3 bytes (to reach 16-align).
    const accts = [_]ser.AccountInput{
        .{
            .pubkey = .{1} ** 32,
            .owner = .{2} ** 32,
            .lamports = 100,
            .data = data,
            .executable = false,
            .rent_epoch = 0,
            .is_signer = true,
            .is_writable = true,
        },
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{ .virtual_address_space_adjustments = true },
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);
    defer alloc.free(r.input_regions);
    defer alloc.free(r.acc_region_metas);

    // Region 0 = metadata, Region 1 = data, Region 2 = trailing.
    try std.testing.expectEqual(@as(usize, 3), r.input_regions.len);
    const data_region = r.input_regions[1];
    // region_sz == dlen (current size, growable up to address_space_reserved).
    try std.testing.expectEqual(@as(u32, 13), data_region.region_sz);
    // address_space_reserved == dlen + MAX_PERMITTED_DATA_INCREASE (NO pad).
    try std.testing.expectEqual(
        @as(u64, 13 + 10240),
        data_region.address_space_reserved,
    );
}

test "PR-3 vasa-off: input_regions stays empty (MODE 1)" {
    const alloc = std.testing.allocator;
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &.{},
        .{}, // all flags default-off
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);
    try std.testing.expectEqual(@as(usize, 0), r.input_regions.len);
    try std.testing.expectEqual(@as(usize, 0), r.acc_region_metas.len);
}

test "M5 NotImplemented: account_data_direct_mapping" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        ser.SerializeError.NotImplemented,
        ser.serializeParametersAligned(
            alloc,
            ZERO_KEY,
            &.{},
            &.{},
            .{ .account_data_direct_mapping = true },
        ),
    );
}

test "SIMD-0449 direct_account_pointers: trailer byte-exact vs rc.1 golden vector" {
    // Anchored to the rc.1 program-runtime golden vector
    // (AGAVE-GOLDEN-VECTOR-HARNESS-2026-06-21.md): deterministic instruction
    // accounts with tx-indexes [1,1,2,3,4,4,5,6] (duplicates at positions 1 & 5),
    // is_writable iff position >= 4, data lengths [5,5,9,0,5,5,9,0]. The trailer
    // pointers depend only on data lengths + the dedup pattern (not owner/data
    // content), so we reproduce those exactly.
    const alloc = std.testing.allocator;
    const program_id: [32]u8 = @splat(0xAA);
    const owner: [32]u8 = @splat(0xBB); // irrelevant to the trailer
    const d5 = [_]u8{ 1, 2, 3, 4, 5 };
    const d9 = [_]u8{ 11, 12, 13, 14, 15, 16, 17, 18, 19 };

    const Spec = struct { pk: u8, data: []const u8, writable: bool };
    const specs = [_]Spec{
        .{ .pk = 0x11, .data = &d5, .writable = false }, // pos 0
        .{ .pk = 0x11, .data = &d5, .writable = false }, // pos 1 (dup of 0)
        .{ .pk = 0x22, .data = &d9, .writable = false }, // pos 2
        .{ .pk = 0x33, .data = &.{}, .writable = false }, // pos 3
        .{ .pk = 0x44, .data = &d5, .writable = true }, // pos 4
        .{ .pk = 0x44, .data = &d5, .writable = true }, // pos 5 (dup of 4)
        .{ .pk = 0x55, .data = &d9, .writable = true }, // pos 6
        .{ .pk = 0x66, .data = &.{}, .writable = true }, // pos 7
    };
    var accts: [8]ser.AccountInput = undefined;
    for (&accts, specs) |*a, s| {
        a.* = .{
            .pubkey = @splat(s.pk),
            .owner = owner,
            .lamports = 0,
            .data = s.data,
            .executable = false,
            .rent_epoch = 0,
            .is_signer = false,
            .is_writable = s.writable,
        };
    }
    const ix_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    const off = try ser.serializeParametersAligned(alloc, program_id, &ix_data, &accts, .{});
    defer alloc.free(off.bytes);
    defer alloc.free(off.account_layouts);
    const on = try ser.serializeParametersAligned(alloc, program_id, &ix_data, &accts, .{ .direct_account_pointers = true });
    defer alloc.free(on.bytes);
    defer alloc.free(on.account_layouts);

    // SIMD-0449 only APPENDS — the prefix must be byte-identical.
    try std.testing.expect(on.bytes.len > off.bytes.len);
    try std.testing.expectEqualSlices(u8, off.bytes, on.bytes[0..off.bytes.len]);

    const trailer = on.bytes[off.bytes.len..];
    const pad = (8 - (off.bytes.len % 8)) % 8;
    try std.testing.expectEqual(@as(usize, pad + 8 * 8), trailer.len);
    for (trailer[0..pad]) |b| try std.testing.expectEqual(@as(u8, 0), b);

    // Golden pointers from the rc.1 dump (LE u64), incl the dup pairs (0,1) and (4,5).
    const golden = [_]u64{
        0x400000008, 0x400000008, 0x400002878, 0x4000050e8,
        0x400007948, 0x400007948, 0x40000a1b8, 0x40000ca28,
    };
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const got = std.mem.readInt(u64, trailer[pad + i * 8 ..][0..8], .little);
        try std.testing.expectEqual(golden[i], got);
    }
}

test "SIMD-0449 vasa+dm+0449 (LIVE regime): trailer byte-exact vs rc.1 three-axis golden vector" {
    // The LIVE testnet regime once SIMD-0449 activates: vasa (SIMD-0460) and dm
    // (SIMD-0257) are ALREADY active cluster-wide, so every tx serializes with
    // all three bools true. rc.1's own test suite never exercises this triple —
    // the golden values below were emitted by extending program-runtime
    // serialization.rs::vexor_dump_simd0449 to dump {vasa=true, dm=true,
    // direct=true}: `cargo test -p solana-program-runtime
    // --features agave-unstable-api,dev-context-only-utils --lib
    // serialization::tests::vexor_dump_simd0449 -- --nocapture` (2026-06-26).
    // Canonical result: buf_len=768, program_id ends @ host offset 699, 5 zero
    // pad bytes [699..704], then 8 u64-LE marker vm_addrs at [704..768] that are
    // IDENTICAL to the flat-path golden (the buffer/vaddr drift is ≡0 mod 8, so
    // the trailer values are mode-invariant). Same instruction accounts as the
    // flat test: tx-indexes [1,1,2,3,4,4,5,6], data lengths [5,5,9,0,5,5,9,0],
    // dups at positions 1→0 and 5→4. Pre-fix this combo returned NotImplemented.
    const alloc = std.testing.allocator;
    const program_id: [32]u8 = @splat(0xAA);
    const owner: [32]u8 = @splat(0xBB); // irrelevant to the trailer values
    const d5 = [_]u8{ 1, 2, 3, 4, 5 };
    const d9 = [_]u8{ 11, 12, 13, 14, 15, 16, 17, 18, 19 };

    const Spec = struct { pk: u8, data: []const u8, writable: bool };
    const specs = [_]Spec{
        .{ .pk = 0x11, .data = &d5, .writable = false }, // pos 0
        .{ .pk = 0x11, .data = &d5, .writable = false }, // pos 1 (dup of 0)
        .{ .pk = 0x22, .data = &d9, .writable = false }, // pos 2
        .{ .pk = 0x33, .data = &.{}, .writable = false }, // pos 3
        .{ .pk = 0x44, .data = &d5, .writable = true }, // pos 4
        .{ .pk = 0x44, .data = &d5, .writable = true }, // pos 5 (dup of 4)
        .{ .pk = 0x55, .data = &d9, .writable = true }, // pos 6
        .{ .pk = 0x66, .data = &.{}, .writable = true }, // pos 7
    };
    var accts: [8]ser.AccountInput = undefined;
    for (&accts, specs) |*a, s| {
        a.* = .{
            .pubkey = @splat(s.pk),
            .owner = owner,
            .lamports = 0,
            .data = s.data,
            .executable = false,
            .rent_epoch = 0,
            .is_signer = false,
            .is_writable = s.writable,
        };
    }
    const ix_data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    // The combo MUST NOT error now (was SerializeError.NotImplemented pre-fix).
    const r = try ser.serializeParametersAligned(alloc, program_id, &ix_data, &accts, .{
        .virtual_address_space_adjustments = true,
        .account_data_direct_mapping = true,
        .direct_account_pointers = true,
    });
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);
    defer if (r.input_regions.len > 0) alloc.free(r.input_regions);
    defer if (r.acc_region_metas.len > 0) alloc.free(r.acc_region_metas);

    // (1) Canonical total length: dm buffer 699 + 5 pad + 8*8 trailer = 768.
    try std.testing.expectEqual(@as(usize, 768), r.bytes.len);

    // (1b) MODE-3 region GEOMETRY byte-exact vs the rc.1 dump (vm_addr − INPUT
    //      START, len). The program reads the 0449 trailer THROUGH this vmap, so
    //      the TRAILING region must grow to cover pad+N*8 — verifying it here is
    //      the load-bearing check that the buffer-byte check alone misses.
    //      `VEXORGV3AX region[i] vm_addr/len` from
    //      serialization::tests::vexor_dump_simd0449 {vasa,dm,direct}=true.
    //      Region WRITABILITY of the per-account DATA regions is deliberately NOT
    //      asserted: under dm Agave derives it from a runtime property
    //      (`can_data_be_changed() && !is_shared()`, serialization.rs:42-50) and
    //      installs a CoW access-violation handler, so writes land regardless of
    //      the flag (Vexor maps writable=is_writable + writes directly — bank-
    //      equivalent, and unrelated to this SIMD-0449 change).
    const reg_off = [_]u64{ 0x0, 0x60, 0x2865, 0x28d0, 0x50d9, 0x5140, 0x7940, 0x79a0, 0xa1a5, 0xa210, 0xca19, 0xca80, 0xf280 };
    const reg_len = [_]u64{ 96, 5, 107, 9, 103, 0, 96, 5, 107, 9, 103, 0, 128 };
    try std.testing.expectEqual(reg_off.len, r.input_regions.len);
    for (r.input_regions, 0..) |rg, ri| {
        try std.testing.expectEqual(reg_off[ri], rg.vaddr_offset);
        try std.testing.expectEqual(reg_len[ri], rg.region_sz);
    }
    // (1c) The TRAILING region (the one my fix grows) holds the trailer: it must
    //      be a writable, contiguous region whose [vaddr_offset, +region_sz)
    //      reaches the buffer end so the program can read all N pointers.
    const tail = r.input_regions[r.input_regions.len - 1];
    try std.testing.expectEqual(@as(u64, 0xf280), tail.vaddr_offset);
    try std.testing.expectEqual(@as(u64, 128), tail.region_sz);
    try std.testing.expect(tail.is_writable);

    // (2) The 5 pad bytes [699..704] are zero; trailer [704..768] decodes to the
    //     golden marker vm_addrs (incl dup pairs 0&1 and 4&5) — byte-identical to
    //     the flat-path golden at serialize_test.zig:497-500.
    const golden = [_]u64{
        0x400000008, 0x400000008, 0x400002878, 0x4000050e8,
        0x400007948, 0x400007948, 0x40000a1b8, 0x40000ca28,
    };
    const trailer_start = r.bytes.len - golden.len * 8; // 704
    for (r.bytes[699..trailer_start]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    var i: usize = 0;
    while (i < golden.len) : (i += 1) {
        const got = std.mem.readInt(u64, r.bytes[trailer_start + i * 8 ..][0..8], .little);
        try std.testing.expectEqual(golden[i], got);
    }

    // (4) Each trailer entry == that account's own marker addr (vm_key_addr − 8),
    //     including duplicates carrying the original's addr.
    i = 0;
    while (i < accts.len) : (i += 1) {
        const got = std.mem.readInt(u64, r.bytes[trailer_start + i * 8 ..][0..8], .little);
        try std.testing.expectEqual(r.account_layouts[i].vm_key_addr - 8, got);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. DESERIALIZE-RETURN ROUND-TRIP
// ─────────────────────────────────────────────────────────────────────────────

test "M5 deserialize round-trip: untouched buffer reads back originals" {
    const alloc = std.testing.allocator;
    const k: [32]u8 = @splat(0x77);
    const own: [32]u8 = @splat(0x88);
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    const accts = [_]ser.AccountInput{
        mkAccount(k, own, &data, true),
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    var outs = [_]ser.AccountOutput{undefined};
    try ser.deserializeReturn(r.bytes, &outs, r.account_layouts, false);

    try std.testing.expectEqual(@as(u64, 1234), outs[0].lamports);
    try std.testing.expectEqual(@as(usize, 9), outs[0].data_len);
    try std.testing.expectEqualSlices(u8, &data, outs[0].data);
    try std.testing.expectEqualSlices(u8, &own, &outs[0].owner);
}

test "M5 deserialize round-trip: in-place mutation is visible on return" {
    const alloc = std.testing.allocator;
    const k: [32]u8 = @splat(0x77);
    const data = [_]u8{ 0xAA, 0xBB };
    const accts = [_]ser.AccountInput{
        mkAccount(k, FF_KEY, &data, true),
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    // Simulate a BPF program: bump lamports, mutate first data byte, change owner.
    std.mem.writeInt(
        u64,
        r.bytes[r.account_layouts[0].host_lamports_offset..][0..8],
        9999,
        .little,
    );
    r.bytes[r.account_layouts[0].host_data_offset] = 0xCC;
    @memset(r.bytes[r.account_layouts[0].host_owner_offset..][0..32], 0x42);

    var outs = [_]ser.AccountOutput{undefined};
    try ser.deserializeReturn(r.bytes, &outs, r.account_layouts, false);

    try std.testing.expectEqual(@as(u64, 9999), outs[0].lamports);
    try std.testing.expectEqual(@as(u8, 0xCC), outs[0].data[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), outs[0].data[1]); // unchanged
    const exp_owner: [32]u8 = @splat(0x42);
    try std.testing.expectEqualSlices(u8, &exp_owner, &outs[0].owner);
}

test "M5 deserialize: oversized post_len is rejected" {
    const alloc = std.testing.allocator;
    const k: [32]u8 = @splat(0x77);
    const data = [_]u8{1};
    const accts = [_]ser.AccountInput{
        mkAccount(k, FF_KEY, &data, true),
    };
    const r = try ser.serializeParametersAligned(
        alloc,
        ZERO_KEY,
        &.{},
        &accts,
        .{},
    );
    defer alloc.free(r.bytes);
    defer alloc.free(r.account_layouts);

    // Force post_len = pre + MAX_REALLOC + 1 — must trigger InvalidRealloc.
    const dlen_off = r.account_layouts[0].host_data_offset - 8;
    const bad_len: u64 = 1 + @as(u64, ser.MAX_REALLOC) + 1;
    std.mem.writeInt(u64, r.bytes[dlen_off..][0..8], bad_len, .little);

    var outs = [_]ser.AccountOutput{undefined};
    try std.testing.expectError(
        ser.SerializeError.InvalidRealloc,
        ser.deserializeReturn(r.bytes, &outs, r.account_layouts, false),
    );
}
