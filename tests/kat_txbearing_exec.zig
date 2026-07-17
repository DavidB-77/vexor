//! TX-BEARING PRODUCE→EXECUTE→FREEZE KAT (flip-blockers e/f — the produce-parity execution gate).
//!
//! WHAT THIS PROVES (the OFFLINE increment of tx-bearing block production):
//!   The existing produce-parity KAT (block_produce.zig:755) produces tx-bearing bytes + checks PoH
//!   framing, but does NOT execute the txs or compare bank state. This KAT closes that gap OFFLINE:
//!     1. seed a small synthetic account set (funded payer + recipient) + a parent bank_hash;
//!     2. queue a KNOWN System-transfer tx, produce a tx-bearing block via the REAL produceSlotBytes
//!        loopback path (gate=null, exactly what the live loopback-only producer runs);
//!     3. REPLAY the produced bytes: re-parse the entry batch, extract the transfer amount FROM THE
//!        ROUND-TRIPPED WIRE (not a side variable), drive the tx through the REAL System instruction
//!        processor `system.executeTransfer` (the same processor the live replay path dispatches to);
//!     4. fold the post-state through the REAL bank_hash primitives (accountLtHash + computeBankHash,
//!        byte-mirrored from bank.zig — see citations below) and FREEZE a bank_hash;
//!     5. assert: (i) the produced entries round-trip + parse, (ii) the transfer post-balances are
//!        applied (recipient += amount, payer -= amount), (iii) the frozen bank_hash is DETERMINISTIC
//!        (produce→replay twice → identical) AND reflects the executed txs (post-hash ≠ parent-hash).
//!
//! ── HONEST BOUNDARY (what this is NOT) ──────────────────────────────────────────────────────────
//!   * NO offline Agave oracle: there is no byte-for-byte cluster-attested bank_hash to compare to
//!     here. The gate is therefore DETERMINISM + STATE-APPLICATION + HASH-REFLECTS-STATE, not "equals
//!     Agave". A true at-tip parity compare is the operator-supervised LIVE step (still broadcast-gated).
//!   * The KAT AUTHOR re-creates the parse→dispatch→lthash→hash ASSEMBLY that production keeps inside
//!     replay_stage.zig. replay_stage cannot be a standalone test root (it pulls Bank + AccountsDb +
//!     the whole validator), so `pushSlotForReplayWithParent` is not reachable from a KAT. This proves
//!     the COMPONENTS (produceSlotBytes, system.executeTransfer, accountLtHash, computeBankHash) are
//!     individually correct and COMPOSE — it does NOT prove replay_stage's wiring invokes them in this
//!     exact order. That ordering is verified live (the existing bank-exact voting + accepted blocks).
//!   * The bank_hash primitives are BYTE-MIRRORED from bank.zig (not imported) to avoid dragging the
//!     full Bank module graph (vex_store stub + rewards + …) into a produce+execute test root. The
//!     mirror is line-cited and the boot-time KAT in vex_crypto/blake3.zig already proves the blake3
//!     backend byte-identical, so the mirror is faithful.
//!
//! Fees are intentionally SCOPED OUT of this KAT (gate=null, no fee debit): fee settlement needs a full
//! Bank and is covered by the admitTxSeq + cost-tracker KATs. Here we execute ONLY the transfer so the
//! balance assertion is clean. Run: zig build test-txbearing-exec

const std = @import("std");
const block_produce = @import("block_produce");
const banking_stage = @import("banking_stage");
const tx_ingest = @import("tx_ingest");

const system = @import("system");
const vex_crypto = @import("vex_crypto");

const Hash = [32]u8;
const LtHash = vex_crypto.LtHash;
// AccountMeta/Pubkey come from the `system` module so they are the EXACT types
// system.executeTransfer expects (same-module identity; see system.zig re-exports).
const AccountMeta = system.AccountMeta;
const Pubkey = system.Pubkey;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// BYTE-MIRRORED bank_hash primitives (the REAL ones live in bank.zig; mirrored here to avoid the full
// Bank module graph — see file header). Each is line-cited and identical to the production body.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Mirror of bank.zig:747 `Bank.accountLtHash` (fd_hashes.c:30-40). 2048-byte BLAKE3 XOF over
/// (lamports_le ‖ data ‖ executable_flag ‖ owner ‖ pubkey), read as 1024 × u16 LE. Zero-lamport
/// accounts excluded. Uses the SAME vex_crypto.blake3.Blake3 the production accountLtHash uses.
fn accountLtHash(pubkey: *const [32]u8, owner: *const [32]u8, lamports: u64, executable: bool, data: []const u8) LtHash {
    if (lamports == 0) return LtHash.init();
    const executable_flag: u8 = if (executable) 1 else 0;
    var b3 = vex_crypto.blake3.Blake3.init(.{});
    var lamports_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &lamports_le, lamports, .little);
    b3.update(&lamports_le);
    b3.update(data);
    b3.update(&[_]u8{executable_flag});
    b3.update(owner);
    b3.update(pubkey);
    var out: [2048]u8 = undefined;
    b3.final(&out);
    var lt = LtHash.init();
    for (0..1024) |i| lt.elements[i] = std.mem.readInt(u16, out[i * 2 ..][0..2], .little);
    return lt;
}

/// Mirror of bank.zig:874 `Bank.computeBankHash` (fd_hashes.c:60-69).
///   step1 = sha256(prev_bank_hash ‖ signature_count_le ‖ poh_hash)
///   bank_hash = sha256(step1 ‖ lthash_2048_bytes)
fn computeBankHash(lthash: *const LtHash, prev_bank_hash: *const Hash, poh_hash: *const Hash, signature_count: u64) Hash {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(prev_bank_hash);
    var sig_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sig_le, signature_count, .little);
    sha.update(&sig_le);
    sha.update(poh_hash);
    var step1: [32]u8 = undefined;
    sha.final(&step1);

    var sha2 = std.crypto.hash.sha2.Sha256.init(.{});
    sha2.update(&step1);
    var lthash_bytes: [2048]u8 = undefined;
    for (0..1024) |i| std.mem.writeInt(u16, lthash_bytes[i * 2 ..][0..2], lthash.elements[i], .little);
    sha2.update(&lthash_bytes);
    var result: [32]u8 = undefined;
    sha2.final(&result);
    return result;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Synthetic account model + bank_hash over the full account set.
// ════════════════════════════════════════════════════════════════════════════════════════════════

const Account = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    executable: bool = false,
    data: []const u8 = &.{},
};

/// Full lthash recompute over a non-zero account set (the bank_hash lthash input). Order-independent:
/// lattice-hash addition is commutative, so this is independent of account ordering.
fn lthashOfAccounts(accounts: []const Account) LtHash {
    var lt = LtHash.init();
    for (accounts) |acc| {
        if (acc.lamports == 0) continue; // excluded (fd_hashes.c:30-32)
        var leaf = accountLtHash(&acc.pubkey, &acc.owner, acc.lamports, acc.executable, acc.data);
        lt.wrappingAdd(&leaf);
    }
    return lt;
}

/// Freeze: bank_hash over (parent_hash, poh_hash=blockhash, signature_count, lthash(accounts)).
fn freezeBankHash(accounts: []const Account, parent_hash: *const Hash, blockhash: *const Hash, signature_count: u64) Hash {
    const lt = lthashOfAccounts(accounts);
    return computeBankHash(&lt, parent_hash, blockhash, signature_count);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Build a REAL legacy System-transfer tx: 2 account keys [payer(signer,writable), recipient(writable)],
// 1 instruction program=System (key index 2, readonly-unsigned), data = [2,0,0,0] ++ amount_le(u64).
// Mirrors the wire layout tx_ingest.parse consumes. Header: num_required_sigs=1, num_ro_signed=0,
// num_ro_unsigned=1 (the System program id is a readonly-unsigned key).
// ════════════════════════════════════════════════════════════════════════════════════════════════
fn buildTransferTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, out: []u8) []u8 {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    var mpos: usize = 1 + 64; // compactU16(1 signature) = 0x01, then 64-byte signature
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 1; // num_readonly_unsigned (the System program key)
    mpos += 3;
    out[mpos] = 3; // compactU16: 3 account keys (payer, recipient, system-program)
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // [0] payer (signer, writable)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient); // [1] recipient (writable)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM_ID); // [2] system program (readonly-unsigned)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash); // recent blockhash
    mpos += 32;
    // instructions: 1 instruction.
    out[mpos] = 1; // compactU16: 1 instruction
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (system program)
    mpos += 1;
    out[mpos] = 2; // compactU16: 2 account indices
    mpos += 1;
    out[mpos] = 0; // account index 0 = payer
    out[mpos + 1] = 1; // account index 1 = recipient
    mpos += 2;
    out[mpos] = 12; // compactU16: 12 data bytes (4-byte discriminator + 8-byte amount)
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], 2, .little); // SystemInstruction::Transfer = 2
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little); // lamports
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

/// Extract the System-transfer amount from a round-tripped tx wire: the instruction data is the last
/// 12 bytes (program_id_index, 2 account indices, then data_len=12, [2,0,0,0]++amount_le). We re-parse
/// from `parsed.instructions_offset` to find the data, faithful to the wire layout (not a side var).
fn extractTransferAmount(wire: []const u8, parsed: tx_ingest.ParsedTx) ?u64 {
    var p = parsed.instructions_offset;
    if (p >= wire.len) return null;
    const num_ix = wire[p]; // single-byte compactU16 for small counts
    p += 1;
    if (num_ix != 1) return null;
    if (p + 1 > wire.len) return null;
    p += 1; // program_id_index
    if (p >= wire.len) return null;
    const num_accts = wire[p];
    p += 1;
    p += num_accts; // skip account index list
    if (p >= wire.len) return null;
    const data_len = wire[p];
    p += 1;
    if (data_len != 12 or p + 12 > wire.len) return null;
    const disc = std.mem.readInt(u32, wire[p..][0..4], .little);
    if (disc != 2) return null; // not a Transfer
    return std.mem.readInt(u64, wire[p + 4 ..][0..8], .little);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// THE KAT
// ════════════════════════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

/// Produce a tx-bearing block carrying ONE known transfer, replay it through the real System processor
/// + real bank_hash primitives, and return {frozen bank_hash, post-balances}. Pure → deterministic.
const ReplayResult = struct {
    bank_hash: Hash,
    payer_post: u64,
    recipient_post: u64,
    blockhash: Hash,
    records: usize,
};

fn produceThenReplay(
    a: std.mem.Allocator,
    kp: std.crypto.sign.Ed25519.KeyPair,
    recipient: [32]u8,
    blockhash_recent: [32]u8,
    amount: u64,
    payer_start: u64,
    recipient_start: u64,
    parent_hash: Hash,
) !ReplayResult {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    const seed: Hash = [_]u8{0x5E} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;

    // 1. queue the known transfer tx into the mempool.
    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    var txbuf: [512]u8 = undefined;
    const tx = buildTransferTx(kp, recipient, blockhash_recent, amount, &txbuf);
    try banking.queueTransaction(tx, 0, false, .tpu);

    // 2. produce a tx-bearing block via the REAL loopback path (gate=null, generous CU limit).
    var blockhash: Hash = undefined;
    const bytes = try block_produce.produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, null, block_produce.MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // 3. REPLAY: seed the account set, then walk the produced entries; for each tx entry drive the
    //    REAL System processor with the amount EXTRACTED FROM THE ROUND-TRIPPED WIRE.
    var payer = AccountMeta{ .pubkey = Pubkey.init(kp.public_key.bytes), .lamports = payer_start, .owner = Pubkey.init(SYSTEM_ID), .executable = false, .rent_epoch = 0, .data = &.{} };
    var recip = AccountMeta{ .pubkey = Pubkey.init(recipient), .lamports = recipient_start, .owner = Pubkey.init(SYSTEM_ID), .executable = false, .rent_epoch = 0, .data = &.{} };

    const count = try block_produce.readEntryCount(bytes);
    var offset: usize = 8; // past the u64 count prefix
    var records: usize = 0;
    var sig_count: u64 = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try block_produce.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            // (i) round-trip: parse the single tx blob back out of the produced bytes (one tx per
            //     entry → the blob spans tx.len bytes from txs_offset).
            var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const tx_blob = bytes[h.txs_offset..][0..tx.len];
            try testing.expectEqualSlices(u8, tx, tx_blob); // round-trip byte-identical
            const parsed = try tx_ingest.parse(tx_blob, &ssig, &skey);
            sig_count +|= parsed.num_required_sigs;

            // (ii) execute the transfer with the amount from the round-tripped wire.
            const amt = extractTransferAmount(tx_blob, parsed) orelse return error.NotATransfer;
            try system.executeTransfer(&payer, &recip, amt); // REAL System processor

            records += 1;
            offset = h.txs_offset + tx.len;
        } else {
            offset = h.txs_offset;
        }
    }

    // 4. FREEZE: bank_hash over the post-execution account set (poh_hash = produced blockhash).
    const accounts = [_]Account{
        .{ .pubkey = kp.public_key.bytes, .lamports = payer.lamports, .owner = SYSTEM_ID, .data = &.{} },
        .{ .pubkey = recipient, .lamports = recip.lamports, .owner = SYSTEM_ID, .data = &.{} },
    };
    const bank_hash = freezeBankHash(&accounts, &parent_hash, &blockhash, sig_count);

    return .{ .bank_hash = bank_hash, .payer_post = payer.lamports, .recipient_post = recip.lamports, .blockhash = blockhash, .records = records };
}

test "tx-bearing produce→execute→freeze: balances applied, bank_hash deterministic + reflects state" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const recipient: [32]u8 = [_]u8{0x99} ** 32;
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    const bh_recent: [32]u8 = [_]u8{0x33} ** 32;
    const amount: u64 = 1_000_000;
    const payer_start: u64 = 5_000_000;
    const recipient_start: u64 = 2_000_000;
    const parent_hash: Hash = [_]u8{0xCA} ** 32;

    const r1 = try produceThenReplay(a, kp, recipient, bh_recent, amount, payer_start, recipient_start, parent_hash);
    const r2 = try produceThenReplay(a, kp, recipient, bh_recent, amount, payer_start, recipient_start, parent_hash);

    // (i) the block carried exactly one record entry (one tx).
    try testing.expectEqual(@as(usize, 1), r1.records);

    // (ii) the transfer post-balances are applied (recipient += amount, payer -= amount).
    try testing.expectEqual(payer_start - amount, r1.payer_post);
    try testing.expectEqual(recipient_start + amount, r1.recipient_post);

    // (iii.a) DETERMINISM: produce→replay twice → identical frozen bank_hash (and identical blockhash).
    try testing.expectEqualSlices(u8, &r1.bank_hash, &r2.bank_hash);
    try testing.expectEqualSlices(u8, &r1.blockhash, &r2.blockhash);

    // (iii.b) the frozen bank_hash REFLECTS the executed txs: it must differ from the bank_hash of the
    //         PARENT (pre-transfer) account set computed over the SAME parent_hash/blockhash/sig_count.
    //         (If execution were a no-op the post-state lthash == pre-state lthash ⇒ equal hashes.)
    const pre_accounts = [_]Account{
        .{ .pubkey = kp.public_key.bytes, .lamports = payer_start, .owner = SYSTEM_ID, .data = &.{} },
        .{ .pubkey = recipient, .lamports = recipient_start, .owner = SYSTEM_ID, .data = &.{} },
    };
    const pre_hash = freezeBankHash(&pre_accounts, &parent_hash, &r1.blockhash, 1);
    try testing.expect(!std.mem.eql(u8, &pre_hash, &r1.bank_hash));

    // Sanity: total lamports conserved (no fee debit in this scope) — a transfer moves, never mints.
    try testing.expectEqual(payer_start + recipient_start, r1.payer_post + r1.recipient_post);
}

test "extractTransferAmount round-trips the wire amount (not a side variable)" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x72} ** 32);
    const recipient: [32]u8 = [_]u8{0x88} ** 32;
    const bh: [32]u8 = [_]u8{0x44} ** 32;
    const amount: u64 = 424_242;
    var buf: [512]u8 = undefined;
    const tx = buildTransferTx(kp, recipient, bh, amount, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(tx, &ssig, &skey);
    try testing.expectEqual(@as(?u64, amount), extractTransferAmount(tx, parsed));
    // sigverify the built tx (it must be a valid, well-formed transaction).
    try testing.expect(tx_ingest.verifySignatures(parsed));
}
