//! kat_commit_owner_414352136.zig — regression KAT for the PROVEN carrier
//! @414352136: intra-tx owner-change LOSS in the V2 mutation commit layer.
//!
//! Ground truth (cluster bank_hash_details @414352136, Agave 4.1.0-beta.3,
//! artifacts carrier-414352136/):
//!   ATA   7m7NUeprWXjHSkV9Tqxc4XYWSEUCDKdk462iMpN4snvQ
//!   owner TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb  (Token-2022)
//!   lamports 2_074_080, executable=false, 170-byte Token-2022 account
//!   (mint 3f5052de…, wallet e04a3656…, amount 1_000_000, ImmutableOwner ext).
//! Vexor committed the SAME lamports + data but owner = ALL-ZEROS (recorder
//! slot-414352136.writes.jsonl: owner=0000…, new_lam=2074080, new_dlen=170).
//!
//! Mechanism (replay_stage.zig commitV2Mutations, pre-fix):
//!   mutation A (ATA CreateIdempotent): new_owner=Token-2022 → committed OK.
//!   mutation B (TransferChecked, data-only): the dispatch snapshot already
//!   saw A's owner via the r75 pending_writes overlay, so new_owner=null; the
//!   commit layer then re-derived owner from `m.new_owner orelse pre_owner`
//!   where pre_owner came from db.getAccountInSlot (PRE-TX durable state) →
//!   MISS for a same-tx-created account → System zeros. The slot-flush dedup
//!   (replay_stage.zig:6232-6238, last-write-wins) + the freeze per-pubkey lt
//!   aggregation (bank.zig:3243, LAST new_lt) persisted B's zero owner and
//!   poisoned last_new_lt → accounts_lt_hash → bank_hash divergence.
//!
//! The fix commits `m.owner` — the dispatch layer's DISCRIMINATED post-state
//! owner (v2_dispatch.zig:1311/1397 out-vs-canon RULE#15+DM-lamport
//! discrimination; :417/:589/:1453 + W6B trampoline all populate post-state)
//! — and resolves pre-state (old_lt/executable/rent_epoch) through the same
//! r75-bug-class-c pending_writes overlay used by the dispatch snapshot
//! builder.
//!
//! This KAT drives the REAL `replay_stage.commitV2Mutations` (made pub for
//! this test) against a real Bank + AccountsDb with the carrier's exact
//! pubkeys/owner/lamports/data. PRE-FIX the surviving (last) pending write
//! carries owner=zeros → test FAILS; with the fix it carries Token-2022 and
//! the matching new_lt → PASSES.
//!
//! Run: zig build test-commit-owner-414352136

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_store = @import("vex_store");
const vex_crypto = @import("vex_crypto");
const vex_bpf = @import("vex_bpf");
const core = @import("core");

const AccountsDb = vex_store.accounts.AccountsDb;
const Bank = vex_svm.Bank;
const Hash = vex_svm.Hash;
const replay = vex_svm.replay_stage;
const Pubkey = core.Pubkey;
const AccountMutation = vex_bpf.AccountMutation;

// ── base58 decode (comptime; same helper as cpi_carrier_dispatch_test.zig) ──
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn b58(comptime s: []const u8) [32]u8 {
    @setEvalBranchQuota(100000);
    var bytes: [64]u8 = [_]u8{0} ** 64;
    var len: usize = 0;
    for (s) |c| {
        const di = std.mem.indexOfScalar(u8, B58, c) orelse @compileError("bad b58");
        var carry: usize = di;
        var i: usize = 0;
        while (i < len or carry != 0) : (i += 1) {
            if (i < len) carry += @as(usize, bytes[i]) * 58;
            bytes[i] = @intCast(carry & 0xff);
            carry >>= 8;
            if (i + 1 > len) len = i + 1;
        }
    }
    var zeros: usize = 0;
    for (s) |c| {
        if (c == '1') zeros += 1 else break;
    }
    var out: [32]u8 = [_]u8{0} ** 32;
    var j: usize = 0;
    while (j < len) : (j += 1) out[zeros + (len - 1 - j)] = bytes[j];
    return out;
}

// ── carrier vectors (cluster-canonical) ─────────────────────────────────────
const ATA = b58("7m7NUeprWXjHSkV9Tqxc4XYWSEUCDKdk462iMpN4snvQ");
const TOKEN_2022 = b58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const BPF_UPGRADEABLE = b58("BPFLoaderUpgradeab1e11111111111111111111111");
const SYSTEM_ZEROS: [32]u8 = [_]u8{0} ** 32;

/// Cluster-canonical POST bytes (170B Token-2022 account: mint 3f5052de…,
/// wallet-owner e04a3656…, amount=1_000_000 LE @64, state=Initialized @108,
/// AccountType=Account(2) @165 + ImmutableOwner ext TLV) — VERBATIM
/// bank_hash_details @414352136 base64→hex (cluster_414352136_details.json).
const POST_DATA_HEX = "3f5052de57c868beba455c2738963c2be6d7dde150fb9b4dc56e7f1bdfe381e2e04a365607550f530e006150740f3fc73d8b85b0ffaecfa942360882e13f2d1b40420f00000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000207000000";

const RENT_170: u64 = 2_074_080; // (128+170)*3480*2 — matches cluster lamports

fn postData() [170]u8 {
    @setEvalBranchQuota(100000);
    var out: [170]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, POST_DATA_HEX) catch unreachable;
    return out;
}

/// Mutation-A data: the just-created ATA (same layout, amount=0).
fn createData() [170]u8 {
    var out = postData();
    @memset(out[64..72], 0); // amount = 0
    return out;
}

const SEED_SLOT: core.Slot = 0;
const BANK_SLOT: core.Slot = 1;

test "carrier @414352136: same-tx create→data-only write keeps Token-2022 owner (commit layer)" {
    // Arena: commitV2Mutations deep-copies mutation data with bank.allocator
    // and (by design) nothing frees pending_writes data before freeze — an
    // arena absorbs that without tripping std.testing.allocator leak checks.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(path);

    const db = try AccountsDb.init(alloc, path, null);
    defer db.deinit();
    // The ATA is NOT seeded — it does not exist in pre-tx durable state
    // (created inside the carrier tx). This is the exact MISS that made the
    // pre-fix commit layer fall back to System zeros.

    const bank = try Bank.init(alloc, BANK_SLOT, SEED_SLOT, Hash{ .data = [_]u8{0} ** 32 }, vex_crypto.LtHash.init(), Hash{ .data = [_]u8{0} ** 32 });
    defer bank.deinit();

    const post = postData();
    const created = createData();

    // ── mutation A: ATA CreateIdempotent (owner change System→Token-2022) ──
    // Dispatch reports new_owner non-null (owner changed vs its snapshot).
    var data_a = created; // commitV2Mutations deep-copies; stack slice fine
    const muts_a = [_]AccountMutation{.{
        .pubkey = .{ .data = ATA },
        .new_lamports = RENT_170,
        .owner = TOKEN_2022,
        .data = &data_a,
        .new_owner = TOKEN_2022,
    }};
    replay.commitV2Mutations(bank, db, &muts_a);
    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &TOKEN_2022, &bank.pending_writes.items[0].owner.data);

    // ── mutation B: TransferChecked (data-only; dispatch snapshot already saw
    // A's owner via the r75 overlay → new_owner=null, but m.owner ALWAYS
    // carries the discriminated post-state owner) ──
    var data_b = post;
    const muts_b = [_]AccountMutation{.{
        .pubkey = .{ .data = ATA },
        .new_lamports = RENT_170,
        .owner = TOKEN_2022,
        .data = &data_b,
        .new_owner = null, // ← the carrier trigger
    }};
    replay.commitV2Mutations(bank, db, &muts_b);
    try std.testing.expectEqual(@as(usize, 2), bank.pending_writes.items.len);

    // The slot-flush dedup (replay_stage.zig:6232-6238) walks REVERSE and
    // keeps the FIRST hit = the LAST appended write per pubkey. Assert on
    // exactly that surviving write — mutation B's commit.
    const surviving = &bank.pending_writes.items[bank.pending_writes.items.len - 1];
    try std.testing.expectEqualSlices(u8, &ATA, &surviving.pubkey.data);
    try std.testing.expectEqual(RENT_170, surviving.lamports);
    try std.testing.expectEqualSlices(u8, &post, surviving.data);

    // THE carrier assertion: committed owner == Token-2022 (pre-fix: zeros).
    try std.testing.expect(!std.mem.eql(u8, &surviving.owner.data, &SYSTEM_ZEROS));
    try std.testing.expectEqualSlices(u8, &TOKEN_2022, &surviving.owner.data);

    // Lock the lt contribution too: bank.zig:3243 freeze aggregation applies
    // the LAST write's new_lt per pubkey — pre-fix it was computed over the
    // zero owner, diverging accounts_lt_hash even where the durable bytes
    // happened to match.
    const expect_new_lt = Bank.accountLtHash(&ATA, &TOKEN_2022, RENT_170, false, &post);
    try std.testing.expect(surviving.new_lt != null);
    try std.testing.expectEqualSlices(u8, expect_new_lt.asBytes(), surviving.new_lt.?.asBytes());

    // old_lt of the FIRST write (A) must be the identity contribution
    // (account absent pre-slot, lamports=0 short-circuit) — unchanged by the
    // fix (the overlay only engages when an earlier same-slot write exists).
    const first = &bank.pending_writes.items[0];
    const ident = vex_crypto.LtHash.init();
    try std.testing.expect(first.old_lt != null);
    try std.testing.expectEqualSlices(u8, ident.asBytes(), first.old_lt.?.asBytes());
}

test "latent hazard: pre_executable/rent_epoch resolve through same-slot pending writes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(path);

    const db = try AccountsDb.init(alloc, path, null);
    defer db.deinit();

    const bank = try Bank.init(alloc, BANK_SLOT, SEED_SLOT, Hash{ .data = [_]u8{0} ** 32 }, vex_crypto.LtHash.init(), Hash{ .data = [_]u8{0} ** 32 });
    defer bank.deinit();

    // Earlier same-slot write: executable=true, rent_epoch=7 (a native-path
    // write, e.g. loader finalize) — appended directly as the overlay source.
    const PK = [_]u8{0x42} ** 32;
    const OWN = BPF_UPGRADEABLE;
    var prog_bytes = [_]u8{ 1, 2, 3, 4 };
    const w_old = Bank.accountLtHash(&PK, &SYSTEM_ZEROS, 0, false, &[_]u8{});
    const w_new = Bank.accountLtHash(&PK, &OWN, 1_000_000, true, &prog_bytes);
    try bank.collectWrite(.{
        .pubkey = .{ .data = PK },
        .lamports = 1_000_000,
        .owner = .{ .data = OWN },
        .executable = true,
        .rent_epoch = 7,
        .data = &prog_bytes,
        .old_lt = w_old,
        .new_lt = w_new,
    });

    // Later V2 mutation of the same account (data-only). Pre-fix the commit
    // layer read pre-state from db ONLY → miss → executable=false,
    // rent_epoch=maxInt; with the r75 overlay it inherits the same-slot
    // predecessor's executable/rent_epoch.
    var data_b = [_]u8{ 9, 9, 9, 9 };
    const muts = [_]AccountMutation{.{
        .pubkey = .{ .data = PK },
        .new_lamports = 1_000_000,
        .owner = OWN,
        .data = &data_b,
        .new_owner = null,
    }};
    replay.commitV2Mutations(bank, db, &muts);

    const surviving = &bank.pending_writes.items[bank.pending_writes.items.len - 1];
    try std.testing.expectEqual(true, surviving.executable);
    try std.testing.expectEqual(@as(u64, 7), surviving.rent_epoch);
    try std.testing.expectEqualSlices(u8, &OWN, &surviving.owner.data);
    // new_lt must reflect the inherited executable=true.
    const expect_lt = Bank.accountLtHash(&PK, &OWN, 1_000_000, true, &data_b);
    try std.testing.expectEqualSlices(u8, expect_lt.asBytes(), surviving.new_lt.?.asBytes());
}
