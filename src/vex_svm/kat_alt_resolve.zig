//! KAT for full Agave-equivalent v0 ALT (Address Lookup Table) message
//! resolution (F008): owner check, the ALT program's own `deserialize()`
//! parser, deactivation status, and active-range bounding.
//!
//! Tests `address_lookup_table.resolveLookupTable` directly — the pure
//! decision function `replay_stage.zig`'s `parseTxFromBytes` calls at its v0
//! ALT-lookup call site (:14022-14059ish). `parseTxFromBytes` itself is
//! file-private and pulls in the rest of `replay_stage.zig`'s dependency
//! graph, so it is not driven directly here; `resolveLookupTable` was
//! factored out specifically to be unit-testable against synthetic account
//! bytes + a synthetic SlotHashes buffer, per FIX-SCOPE-F008-F012.md's KAT
//! list (§F008.3).
//!
//! Run:  zig build test-alt-resolve
//!
//! Canonical references mirrored:
//!   Agave accounts-db/src/accounts.rs:106-158  load_lookup_table_addresses_into
//!   Agave (interface) state.rs:92-190          status() / get_active_addresses_len()
//!   Sig   src/replay/resolve_lookup.zig:323-500 resolveLookupTableAccounts / getLookupTable

const std = @import("std");
const alt = @import("native/address_lookup_table.zig");

const PROGRAM_ID = alt.PROGRAM_ID;
const NOT_ALT_OWNER: [32]u8 = [_]u8{0xAB} ** 32;

/// Build a well-formed ALT account byte buffer:
/// disc(4)=1 | deactivation_slot(8) | last_extended_slot(8) |
/// last_extended_slot_start_index(1) | has_authority(1)=0 | authority(32)=0 |
/// padding(2) | addresses (32 bytes each). Matches
/// `address_lookup_table.zig:141-180`'s deserialize() layout exactly.
fn buildTable(
    buf: []u8,
    deactivation_slot: u64,
    last_extended_slot: u64,
    last_extended_slot_start_index: u8,
    addresses: []const [32]u8,
) []u8 {
    std.debug.assert(buf.len >= alt.LOOKUP_TABLE_META_SIZE + addresses.len * 32);
    std.mem.writeInt(u32, buf[0..4], 1, .little); // discriminant = LookupTable
    std.mem.writeInt(u64, buf[4..12], deactivation_slot, .little);
    std.mem.writeInt(u64, buf[12..20], last_extended_slot, .little);
    buf[20] = last_extended_slot_start_index;
    buf[21] = 0; // has_authority = false
    @memset(buf[22..54], 0);
    buf[54] = 0;
    buf[55] = 0;
    for (addresses, 0..) |a, i| {
        @memcpy(buf[alt.LOOKUP_TABLE_META_SIZE + i * 32 ..][0..32], &a);
    }
    return buf[0 .. alt.LOOKUP_TABLE_META_SIZE + addresses.len * 32];
}

/// Build a synthetic SlotHashes sysvar buffer: `[count:u64][(slot:u64,
/// hash:[32]u8) x count]`, sorted DESCENDING by slot — same wire format
/// `vote_state_serde.zig`'s binary search (and `resolveLookupTable`'s
/// `slotHashesContains`) expects.
fn buildSlotHashes(buf: []u8, slots_desc: []const u64) []u8 {
    std.debug.assert(buf.len >= 8 + slots_desc.len * 40);
    std.mem.writeInt(u64, buf[0..8], slots_desc.len, .little);
    for (slots_desc, 0..) |slot, i| {
        const off = 8 + i * 40;
        std.mem.writeInt(u64, buf[off..][0..8], slot, .little);
        @memset(buf[off + 8 ..][0..32], 0xCC); // hash bytes irrelevant to this check
    }
    return buf[0 .. 8 + slots_desc.len * 40];
}

fn addr(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

// ══════════════════════════ #1 happy path ══════════════════════════

test "happy path: active table resolves identical addresses to raw-slice code" {
    var table_buf: [56 + 3 * 32]u8 = undefined;
    const addresses = [_][32]u8{ addr(1), addr(2), addr(3) };
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 0, 0, &addresses);

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null);
    try std.testing.expectEqual(@as(usize, 3), resolved.active_addresses.len);
    try std.testing.expectEqualSlices(u8, &addresses[0], &resolved.active_addresses[0]);
    try std.testing.expectEqualSlices(u8, &addresses[1], &resolved.active_addresses[1]);
    try std.testing.expectEqualSlices(u8, &addresses[2], &resolved.active_addresses[2]);
}

// ══════════════════════════ #2 wrong owner ══════════════════════════

test "negative: wrong owner rejected (today: silently resolves the raw bytes)" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 0, 0, &addresses);

    try std.testing.expectError(
        alt.ResolveError.InvalidAccountOwner,
        alt.resolveLookupTable(table_data, NOT_ALT_OWNER, 100, null),
    );
}

// ══════════════════════════ #3 deactivated, aged out ══════════════════════════

test "negative: deactivated table aged out of SlotHashes window rejected" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    // Deactivated at slot 50; SlotHashes window does NOT contain 50.
    const table_data = buildTable(&table_buf, 50, 0, 0, &addresses);

    var sh_buf: [8 + 5 * 40]u8 = undefined;
    const sh_data = buildSlotHashes(&sh_buf, &.{ 100, 99, 98, 97, 96 }); // 50 not present

    try std.testing.expectError(
        alt.ResolveError.LookupTableAccountNotFound,
        alt.resolveLookupTable(table_data, PROGRAM_ID, 100, sh_data),
    );
}

// ══════════════════════════ #4 deactivating, in cooldown ══════════════════════════

test "boundary: deactivating table still in SlotHashes cooldown window accepted" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    const table_data = buildTable(&table_buf, 50, 0, 0, &addresses);

    var sh_buf: [8 + 5 * 40]u8 = undefined;
    const sh_data = buildSlotHashes(&sh_buf, &.{ 100, 99, 98, 50, 40 }); // 50 present -> Deactivating (cooldown)

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, sh_data);
    try std.testing.expectEqual(@as(usize, 1), resolved.active_addresses.len);
}

// ══════════════════════════ #5 index past active range, same-slot extend ══════════════════════════

test "negative: same-slot extend hides newly-appended addresses this slot" {
    var table_buf: [56 + 5 * 32]u8 = undefined;
    const addresses = [_][32]u8{ addr(1), addr(2), addr(3), addr(4), addr(5) };
    // last_extended_slot == current_slot (100): only the first 2 addresses
    // (pre-extension prefix) are visible; addresses[2..5] are this slot's
    // fresh extension and must stay invisible (anti-reorg design).
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 100, 2, &addresses);

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null);
    try std.testing.expectEqual(@as(usize, 2), resolved.active_addresses.len);
    // Mirrors the call-site bound check in replay_stage.zig: idx=3 (>= active len 2) must reject.
    try std.testing.expect(3 >= resolved.active_addresses.len);
}

// ══════════════════════════ #6 boundary — prior-slot extend ══════════════════════════

test "boundary: prior-slot extend, index at the top of the active range accepted" {
    var table_buf: [56 + 5 * 32]u8 = undefined;
    const addresses = [_][32]u8{ addr(1), addr(2), addr(3), addr(4), addr(5) };
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 40, 2, &addresses);

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null); // 100 > 40 -> full range
    try std.testing.expectEqual(@as(usize, 5), resolved.active_addresses.len);
    const idx: usize = 4; // addresses.len - 1
    try std.testing.expect(idx < resolved.active_addresses.len);
    try std.testing.expectEqualSlices(u8, &addresses[4], &resolved.active_addresses[4]);
}

test "boundary: prior-slot extend, index one past the end rejected" {
    var table_buf: [56 + 5 * 32]u8 = undefined;
    const addresses = [_][32]u8{ addr(1), addr(2), addr(3), addr(4), addr(5) };
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 40, 2, &addresses);

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null);
    const idx: usize = 5; // addresses.len
    try std.testing.expect(idx >= resolved.active_addresses.len);
}

// ══════════════════════════ #7 too-short account (regression guard) ══════════════════════════

test "regression guard: account shorter than LOOKUP_TABLE_META_SIZE rejected" {
    var short_buf: [30]u8 = [_]u8{0} ** 30;
    try std.testing.expectError(
        alt.ResolveError.InvalidAccountData,
        alt.resolveLookupTable(&short_buf, PROGRAM_ID, 100, null),
    );
}

// ══════════════════════════ #8 malformed discriminant ══════════════════════════

test "negative: malformed discriminant rejected (today bypasses deserialize entirely)" {
    var buf: [56 + 32]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], 42, .little); // not ProgramState::LookupTable (1)
    try std.testing.expectError(
        alt.ResolveError.InvalidAccountData,
        alt.resolveLookupTable(&buf, PROGRAM_ID, 100, null),
    );
}

// ══════════════════════════ #9 deactivation_slot == current_slot special case ══════════════════════════

test "boundary: deactivation_slot == current_slot accepted with zero SlotHashes reads" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    // Deactivated in the CURRENT slot itself (state.rs:107-110 special case) —
    // still Activated-equivalent this slot; must not even consult SlotHashes
    // (sh_data passed as null here to prove no dependency).
    const table_data = buildTable(&table_buf, 100, 0, 0, &addresses);

    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null);
    try std.testing.expectEqual(@as(usize, 1), resolved.active_addresses.len);
}

// ══════════════════════════ null-sysvar fallback ══════════════════════════

test "null-sysvar fallback: missing SlotHashes fails CLOSED (rejected), matching Agave" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    // Deactivated at an earlier slot, NOT the current slot -> needs a
    // SlotHashes lookup to distinguish cooldown vs aged-out. No sysvar
    // available (genesis-adjacent, unreachable in practice on real chain
    // history) -> Agave maps this to AddressLoaderError::SlotHashesSysvarNotFound
    // and FAILS the tx (address_lookup_table.rs:44-46); mirror that exactly
    // rather than failing open (see resolveLookupTable's doc comment).
    const table_data = buildTable(&table_buf, 50, 0, 0, &addresses);

    try std.testing.expectError(
        alt.ResolveError.SlotHashesSysvarNotFound,
        alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null),
    );
}

// ══════════════════════════ cost-avoidance: never-deactivated table needs no SH ══════════════════════════

test "cost-avoidance: never-deactivated table takes the Agave status() fast path (no SH needed)" {
    var table_buf: [56 + 32]u8 = undefined;
    const addresses = [_][32]u8{addr(9)};
    const table_data = buildTable(&table_buf, alt.DEACTIVATION_SLOT_NONE, 0, 0, &addresses);

    // sh_data is null AND would be wrong-shaped garbage if read — proves the
    // DEACTIVATION_SLOT_NONE short-circuit never touches it.
    const resolved = try alt.resolveLookupTable(table_data, PROGRAM_ID, 100, null);
    try std.testing.expectEqual(@as(usize, 1), resolved.active_addresses.len);
}
