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
    return buildSystemDiscTx(kp, recipient, blockhash, amount, 2, out);
}

/// Like `buildTransferTx` but with a CALLER-CHOSEN System-instruction discriminator, so a KAT can
/// build a lamport-moving System instruction the M2 gate does NOT model (e.g. TransferWithSeed = 11,
/// WithdrawNonceAccount = 5, Assign = 1). The wire layout ([from, to] accounts, data = disc(4) ‖
/// amount(8)) is deliberately kept IDENTICAL to Transfer's so the ONLY variable under test is the
/// discriminator the gate keys on: this is a MECHANISM PROXY (the real TransferWithSeed carries a
/// bincode-String seed and a [from, base, to] account order — see block_produce.zig's EXPLICITLY
/// UNCOVERED note), faithful to the property that matters here — the gate returns null for the
/// discriminator (`lamportMoveAmount`) so the drain is INVISIBLE to `applyLamportEffects`, yet the
/// instruction still moves `amount` from account[0] to account[1] at execution.
fn buildSystemDiscTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, disc: u32, out: []u8) []u8 {
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
    std.mem.writeInt(u32, out[mpos..][0..4], disc, .little); // SystemInstruction discriminator
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little); // lamports
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

/// Build a tx whose single instruction invokes a NON-System program (a synthetic BPF program id at
/// static key index 2). The M2 gate can derive no lamport effect for a non-System program (and a real
/// such program could CPI-drain the fee-payer), so the interim whitelist must REFUSE it. Layout mirrors
/// buildSystemDiscTx but the program key at index 2 is `program_id` instead of the all-zero System id.
fn buildNonSystemProgramTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, program_id: [32]u8, blockhash: [32]u8, out: []u8) []u8 {
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0;
    out[mpos + 2] = 1; // num_readonly_unsigned (the program key)
    mpos += 3;
    out[mpos] = 3; // 3 account keys (payer, recipient, program)
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &program_id); // NON-System program id
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1; // 1 instruction
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (the non-System program)
    mpos += 1;
    out[mpos] = 2; // 2 account indices
    mpos += 1;
    out[mpos] = 0;
    out[mpos + 1] = 1;
    mpos += 2;
    out[mpos] = 4; // 4 data bytes (arbitrary)
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], 0xDEADBEEF, .little);
    mpos += 4;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

/// Build a v0 (versioned) System-transfer tx — the ALT carrier. Even a v0 tx whose static instructions
/// look benign can load extra writable accounts via address-table lookups the wire's static key list
/// cannot resolve (block_produce.zig resolveStaticKey / txCostSum v0-ALT boundary), so the interim
/// whitelist refuses ALL versioned txs. Identical to buildSystemDiscTx(Transfer) but with the 0x80
/// version marker as the first message byte (tx_ingest.parse sets is_versioned).
fn buildV0TransferTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, out: []u8) []u8 {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 0x80; // v0 version marker
    mpos += 1;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0;
    out[mpos + 2] = 1;
    mpos += 3;
    out[mpos] = 3;
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM_ID);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1; // 1 instruction
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 0;
    out[mpos + 1] = 1;
    mpos += 2;
    out[mpos] = 12;
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], 2, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little);
    mpos += 8;
    // NOTE: a fully-formed v0 message also has an address_table_lookups vector here; not appended
    // (matches tx_ingest.zig's own v0 KAT — header/sigverify + is_versioned is all the gate consults).
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
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

/// Like extractTransferAmount but returns the (discriminator, amount) pair for ANY of our synthetic
/// System lamport-movers (Transfer = 2, or the unmodeled-disc proxy built by buildSystemDiscTx) — both
/// share the [from, to] + disc(4)‖amount(8) layout. Used by the gated scenario's replay to apply the
/// TRUE lamport move even for a discriminator the produce-side gate cannot model.
const SystemMove = struct { disc: u32, amount: u64 };
fn extractSystemMove(wire: []const u8, parsed: tx_ingest.ParsedTx) ?SystemMove {
    var p = parsed.instructions_offset;
    if (p >= wire.len) return null;
    const num_ix = wire[p];
    p += 1;
    if (num_ix != 1) return null;
    if (p + 1 > wire.len) return null;
    p += 1; // program_id_index
    if (p >= wire.len) return null;
    const num_accts = wire[p];
    p += 1;
    p += num_accts;
    if (p >= wire.len) return null;
    const data_len = wire[p];
    p += 1;
    if (data_len != 12 or p + 12 > wire.len) return null;
    return .{ .disc = std.mem.readInt(u32, wire[p..][0..4], .little), .amount = std.mem.readInt(u64, wire[p + 4 ..][0..8], .little) };
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

// ════════════════════════════════════════════════════════════════════════════════════════════════
// M1 (TXBEARING-BLOCK-PRODUCTION-PLAN-2026-07-16.md §4 M1 item 1): GATE-BEARING scenarios.
//
// Everything above this point runs with `gate == null` (the file's own honest-boundary section says
// so explicitly) — i.e. it has NEVER exercised `admitTxSeq`, the REAL live gate. That is the actual
// test-coverage gap this milestone closes, not a new production code path.
//
// WIRING: `GateCtx.admit` below is a byte-for-byte mirror of replay_stage.zig's
// `bankAdmitTxForBroadcast` (replay_stage.zig:1818-1853) — same `SeqGateState`, same `admitTxSeq`
// call, same "fee-payer view = a SINGLE FROZEN-PARENT snapshot, looked up once per payer, never
// updated mid-block" semantics. The only difference from production: `bankAdmitTxForBroadcast` reads
// that snapshot from `accounts_db.getAccountInSlot` on the parent bank; this KAT reads it from a fixed
// in-memory map (no AccountsDb dependency here, matching this file's existing byte-mirror discipline
// for the bank_hash primitives above). This is NOT a new pre-filter — it is the REAL `admitTxSeq`,
// invoked the REAL way, through the REAL `produceSlotBytes`.
//
// REAL EXECUTION with a REAL (not re-derived) fee debit: `block_produce.txFee` (block_produce.zig:152)
// is imported directly and applied to a TRUE running balance per payer, in PRODUCED-BLOCK order,
// BEFORE the transfer instruction executes — mirroring both Agave's fee-payer-debit-then-execute
// ordering (`consumer.rs:256+`, cited in the plan's H1 §2 Agave-contrast paragraph) and this
// codebase's own replay_stage.zig fee-debit-then-collectWrite ordering (:8894-8960, and the
// `bank.signature_count += num_sigs_fee` placement that only fires once the fee-debit guard passes).
// A payer whose TRUE balance can't cover the fee is the exact InsufficientFundsForFee -> NotLoaded
// class block_produce.zig:90-97 documents as BLOCK-FATAL (get_first_error -> mark_dead_slot); a payer
// who can pay the fee but not a LATER transfer inside the SAME tx is a TOLERATED inner-instruction
// failure (Executed-with-inner-error), per that same classification table this KAT is honor-bound to
// respect — conflating the two would misrepresent what actually kills a block.
// ════════════════════════════════════════════════════════════════════════════════════════════════

const ScenarioTx = struct {
    recipient: [32]u8,
    amount: u64,
    wire: []const u8,
};

const TxOutcome = struct {
    admitted: bool = false, // did the REAL admitTxSeq gate include this tx in the produced block?
    fee_ok: bool = false, // (meaningful only if admitted) could the TRUE running balance pay the fee?
    exec_ok: bool = false, // (meaningful only if admitted && fee_ok) did the transfer instruction succeed?
};

const GateCtx = struct {
    parent_view: *const std.AutoHashMapUnmanaged([32]u8, block_produce.FeePayerView),
    state: *block_produce.SeqGateState,
    known_blockhashes: []const [32]u8,
    a: std.mem.Allocator,

    /// Byte-for-byte the same call replay_stage.zig:1852 makes — the REAL live gate.
    fn admit(ctx: *anyopaque, tx_wire: []const u8) bool {
        const self: *GateCtx = @ptrCast(@alignCast(ctx));
        var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest.parse(tx_wire, &ssig, &skey) catch return false;
        const fpv = self.parent_view.get(parsed.signer_keys[0]);
        return block_produce.admitTxSeq(self.a, self.state, parsed, tx_wire, self.known_blockhashes, fpv);
    }
};

const ScenarioResult = struct {
    outcomes: [8]TxOutcome,
    bank_hash: Hash,
    any_block_fatal: bool,
};

/// Run `txs` (in priority/packing order, txs[0] highest priority) through the REAL gate + REAL
/// `produceSlotBytes`, then replay ONLY the admitted txs through REAL fee-debit
/// (`block_produce.txFee`) + REAL `system.executeTransfer`, in produced-block order. Returns per-tx
/// outcomes (parallel to `txs`) plus a determinism-checkable bank_hash over the final account set.
fn runGatedScenario(
    a: std.mem.Allocator,
    parent_hash: Hash,
    blockhash_recent: [32]u8,
    payer_keys: []const [32]u8,
    payer_parent_lamports: []const u64,
    recipients: []const [32]u8,
    recipient_parent_lamports: []const u64,
    txs: []const ScenarioTx,
) !ScenarioResult {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    const seed: Hash = [_]u8{0x5E} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;
    std.debug.assert(txs.len <= 8);

    // 1. Parent view: what the REAL gate sees — a single frozen-parent snapshot per payer, never
    //    updated mid-block (mirroring accounts_db.getAccountInSlot on the parent bank).
    var parent_view: std.AutoHashMapUnmanaged([32]u8, block_produce.FeePayerView) = .{};
    defer parent_view.deinit(a);
    for (payer_keys, payer_parent_lamports) |pk, lam| {
        try parent_view.put(a, pk, .{ .lamports = lam, .owner = SYSTEM_ID, .data_len = 0 });
    }

    // 2. Queue all candidate txs, descending priority ⇒ deterministic drain order == `txs` order.
    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    for (txs, 0..) |t, idx| {
        try banking.queueTransaction(t.wire, @intCast(txs.len - idx), false, .tpu);
    }

    // 3. Produce through the REAL gate (admitTxSeq, wired exactly as replay_stage.zig:1818-1853).
    var seq_state = block_produce.SeqGateState{};
    defer seq_state.deinit(a);
    const known = [_][32]u8{blockhash_recent};
    var gctx = GateCtx{ .parent_view = &parent_view, .state = &seq_state, .known_blockhashes = &known, .a = a };
    const gate = block_produce.InclusionGate{ .ctx = &gctx, .admit = GateCtx.admit };

    var blockhash: Hash = undefined;
    const bytes = try block_produce.produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, gate, block_produce.MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // 4. Walk the produced entries; each record entry's tx blob matches exactly one `txs[i].wire`
    //    (all built by buildTransferTx, hence constant length) — mark that candidate admitted, IN
    //    PRODUCED-BLOCK ORDER (the order replay/execution below must respect).
    var outcomes: [8]TxOutcome = [_]TxOutcome{.{}} ** 8;
    var admitted_order: [8]usize = undefined;
    var admitted_count: usize = 0;
    const tx_len = txs[0].wire.len; // all candidates share the same wire length (fixed transfer layout)
    const entry_count = try block_produce.readEntryCount(bytes);
    var offset: usize = 8;
    var i: u64 = 0;
    while (i < entry_count) : (i += 1) {
        const h = try block_produce.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            try testing.expectEqual(@as(u64, 1), h.num_txs); // one tx per record entry (current packer)
            const blob = bytes[h.txs_offset..][0..tx_len];
            var matched = false;
            for (txs, 0..) |t, ti| {
                if (!outcomes[ti].admitted and std.mem.eql(u8, t.wire, blob)) {
                    outcomes[ti].admitted = true;
                    admitted_order[admitted_count] = ti;
                    admitted_count += 1;
                    matched = true;
                    break;
                }
            }
            try testing.expect(matched); // every produced tx must be one of our own candidates
            offset = h.txs_offset + tx_len;
        } else {
            offset = h.txs_offset;
        }
    }

    // 5. Replay ONLY the admitted txs, in produced-block order: REAL fee debit (block_produce.txFee)
    //    against a TRUE running balance, THEN the REAL transfer instruction — Agave's ordering.
    var true_bal: std.AutoHashMapUnmanaged([32]u8, u64) = .{};
    defer true_bal.deinit(a);
    for (payer_keys, payer_parent_lamports) |pk, lam| try true_bal.put(a, pk, lam);
    for (recipients, recipient_parent_lamports) |pk, lam| try true_bal.put(a, pk, lam);

    var any_block_fatal = false;
    var sig_count: u64 = 0;
    for (admitted_order[0..admitted_count]) |ti| {
        const t = txs[ti];
        var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = try tx_ingest.parse(t.wire, &ssig, &skey);
        const payer_key = parsed.signer_keys[0];
        const fee = block_produce.txFee(parsed, t.wire);
        const bal_before = true_bal.get(payer_key) orelse 0;
        if (bal_before < fee) {
            // InsufficientFundsForFee — the exact NotLoaded/BLOCK-FATAL class block_produce.zig:90-97
            // documents. The tx does NOT land (no fee debit, no execution) and per get_first_error /
            // mark_dead_slot (H1 §2's Agave-fatal-classification citation) the WHOLE block is dead.
            outcomes[ti].fee_ok = false;
            any_block_fatal = true;
            continue;
        }
        outcomes[ti].fee_ok = true;
        sig_count += parsed.num_required_sigs; // mirrors bank.signature_count += num_sigs_fee (guarded)
        try true_bal.put(a, payer_key, bal_before - fee);

        // The lamport-moving instruction executes against the POST-fee balance, in produced-block
        // order. A Transfer (disc 2) runs through the REAL production System processor; an unmodeled-
        // disc proxy (buildSystemDiscTx, e.g. TransferWithSeed = 11) applies the SAME [from]-=amount /
        // [to]+=amount lamport effect directly (the Transfer-only executeTransfer cannot dispatch it) —
        // this is the drain the produce-side gate was BLIND to. Both mirror executeTransfer's
        // insufficient-funds semantics: an inner-instruction failure is TOLERATED (fee already paid).
        const mv = extractSystemMove(t.wire, parsed) orelse return error.NotASystemMove;
        if (mv.disc == 2) {
            var from = AccountMeta{ .pubkey = Pubkey.init(payer_key), .lamports = true_bal.get(payer_key).?, .owner = Pubkey.init(SYSTEM_ID), .executable = false, .rent_epoch = 0, .data = &.{} };
            var to = AccountMeta{ .pubkey = Pubkey.init(t.recipient), .lamports = true_bal.get(t.recipient).?, .owner = Pubkey.init(SYSTEM_ID), .executable = false, .rent_epoch = 0, .data = &.{} };
            if (system.executeTransfer(&from, &to, t.amount)) {
                outcomes[ti].exec_ok = true;
                try true_bal.put(a, payer_key, from.lamports);
                try true_bal.put(a, t.recipient, to.lamports);
            } else |_| {
                outcomes[ti].exec_ok = false;
            }
        } else {
            const from_bal = true_bal.get(payer_key).?;
            if (from_bal >= mv.amount) {
                try true_bal.put(a, payer_key, from_bal - mv.amount);
                try true_bal.put(a, t.recipient, true_bal.get(t.recipient).? + mv.amount);
                outcomes[ti].exec_ok = true;
            } else {
                outcomes[ti].exec_ok = false; // inner-instruction failure, fee retained (TOLERATED)
            }
        }
    }

    // 6. Freeze bank_hash over the FINAL true-balance account set — a HARNESS-INTERNAL
    //    determinism/hash-reflects-state sanity check (mirroring the harness above). It does NOT claim
    //    production would actually freeze a block containing a block-fatal tx (it would mark_dead_slot
    //    instead, per step 5's citation) — this is purely "does OUR pipeline behave deterministically."
    var accounts_buf: [16]Account = undefined;
    var n: usize = 0;
    for (payer_keys) |pk| {
        accounts_buf[n] = .{ .pubkey = pk, .lamports = true_bal.get(pk).?, .owner = SYSTEM_ID, .data = &.{} };
        n += 1;
    }
    for (recipients) |pk| {
        accounts_buf[n] = .{ .pubkey = pk, .lamports = true_bal.get(pk).?, .owner = SYSTEM_ID, .data = &.{} };
        n += 1;
    }
    const bank_hash = freezeBankHash(accounts_buf[0..n], &parent_hash, &blockhash, sig_count);

    return .{ .outcomes = outcomes, .bank_hash = bank_hash, .any_block_fatal = any_block_fatal };
}

test "M2 regression: REAL admitTxSeq gate now REFUSES tx B after tx A drains fee-payer P (H1 mechanism CLOSED)" {
    const a = testing.allocator;
    const kp_p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xA1} ** 32);
    const r1: [32]u8 = [_]u8{0xB1} ** 32;
    const r2: [32]u8 = [_]u8{0xB2} ** 32;
    const bh: [32]u8 = [_]u8{0x77} ** 32;
    const parent_hash: Hash = [_]u8{0xCA} ** 32;

    // P's PARENT balance (both the gate's frozen-parent view AND real execution's starting state) —
    // comfortably affords the sequential FEE bookkeeping the gate tracks (a couple of 5,000-lamport
    // fees), but tx A's TRANSFER (which the gate never looks at) drains almost all of it.
    const payer_parent: u64 = 2_000_000;
    // tx A: P -> R1. Chosen so P's TRUE balance after A's fee debit + transfer is 1,000 lamports —
    // below LAMPORTS_PER_SIGNATURE (5,000), so P cannot even pay tx B's FEE, let alone a transfer.
    const amount_a: u64 = payer_parent - block_produce.LAMPORTS_PER_SIGNATURE - 1_000; // 1,994,000
    const amount_b: u64 = 100; // irrelevant — tx B's FEE fails before its instruction ever executes

    var buf_a: [512]u8 = undefined;
    var buf_b: [512]u8 = undefined;
    const wire_a = buildTransferTx(kp_p, r1, bh, amount_a, &buf_a);
    const wire_b = buildTransferTx(kp_p, r2, bh, amount_b, &buf_b);

    const txs = [_]ScenarioTx{
        .{ .recipient = r1, .amount = amount_a, .wire = wire_a },
        .{ .recipient = r2, .amount = amount_b, .wire = wire_b },
    };
    const payer_keys = [_][32]u8{kp_p.public_key.bytes};
    const payer_lamports = [_]u64{payer_parent};
    const recipients = [_][32]u8{ r1, r2 };
    const recipient_lamports = [_]u64{ 0, 0 };

    const result = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);

    // tx A: admitted (P's PARENT view affords it; the gate cannot yet see any drain) and executes
    // cleanly (P's TRUE balance affords the transfer too).
    try testing.expect(result.outcomes[0].admitted);
    try testing.expect(result.outcomes[0].fee_ok);
    try testing.expect(result.outcomes[0].exec_ok);

    // tx B: THIS is the load-bearing assertion, BEFORE→AFTER M2:
    //   BEFORE (M1, probe/txbearing-m1-gate-kat 79479e5): admitted=true, fee_ok=false, any_block_fatal=true
    //     — the gate tracked ONLY fee debits, had zero visibility into tx A's TRANSFER effect, and
    //     (wrongly) admitted tx B using P's stale balance (parent minus ONE fee, not minus A's
    //     1,994,000 transfer); real replay then hit InsufficientFundsForFee -> BLOCK-FATAL.
    //   AFTER (M2, this commit): admitTxSeq now applies tx A's System::Transfer effect to P's tracked
    //     delta (SeqGateState.deltas) BEFORE evaluating tx B, so it correctly sees P's TRUE post-A
    //     balance (1,000 lamports) can't cover tx B's fee (5,000) and REFUSES tx B at admit time — it
    //     never reaches the produced block, so it can never reach real replay/block-fatal at all.
    try testing.expect(!result.outcomes[1].admitted); // GATE now correctly REFUSES tx B
    try testing.expect(!result.outcomes[1].fee_ok); // never replayed (not admitted) — default false
    try testing.expect(!result.any_block_fatal); // no block-fatal tx ever entered the produced block

    // VERDICT for this scenario: the code's own former "adversarial-only, likely transfer-drain"
    // comment (block_produce.zig, previously :487-488) was CONFIRMED reachable by M1 through the
    // ACTUAL admitTxSeq gate — not just plausible in theory — and is now CLOSED by M2's
    // `SeqGateState`/`applyLamportEffects` extension for the System::Transfer / same-fee-payer-as-
    // transfer-source case this scenario exercises. See block_produce.zig's admitTxSeq/
    // applyLamportEffects doc comments for the residual instruction classes M2 does NOT cover.
}

test "M1 benign-burst: REAL admitTxSeq gate + real execution on 6 independent-payer txs (mirrors the 07-10 manual 6-tx burst)" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x55} ** 32;
    const parent_hash: Hash = [_]u8{0xCB} ** 32;
    const N = 6;

    var kps: [N]std.crypto.sign.Ed25519.KeyPair = undefined;
    var payer_keys: [N][32]u8 = undefined;
    var payer_lamports: [N]u64 = undefined;
    var recipients: [N][32]u8 = undefined;
    var recipient_lamports: [N]u64 = undefined;
    var bufs: [N][512]u8 = undefined;
    var wires: [N][]const u8 = undefined;
    var txs: [N]ScenarioTx = undefined;

    var seed_byte: u8 = 0xC1;
    for (0..N) |idx| {
        kps[idx] = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{seed_byte} ** 32);
        seed_byte += 1;
        payer_keys[idx] = kps[idx].public_key.bytes;
        payer_lamports[idx] = 5_000_000; // well-funded, independent of every other payer
        recipients[idx] = [_]u8{seed_byte} ** 32;
        seed_byte += 1;
        recipient_lamports[idx] = 0;
        const amount: u64 = 10_000 * @as(u64, idx + 1); // distinct low values, NO drain relationship
        wires[idx] = buildTransferTx(kps[idx], recipients[idx], bh, amount, &bufs[idx]);
        txs[idx] = .{ .recipient = recipients[idx], .amount = amount, .wire = wires[idx] };
    }

    const result = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);

    // REPORT + ASSERT: this is a genuine unknown, not a formality (plan §4 M1 item 1 / executor brief
    // item 2). If ANY of these fail, H1's specific mechanism is NOT (only) transfer-drain and that must
    // be reported plainly — do not adjust the scenario's amounts/funding to force a pass.
    for (result.outcomes[0..N], 0..) |o, idx| {
        testing.expect(o.admitted) catch |e| {
            std.debug.print("M1 benign-burst FINDING: tx[{d}] NOT admitted by the real gate (independent payer, well-funded) — unexpected\n", .{idx});
            return e;
        };
        testing.expect(o.fee_ok) catch |e| {
            std.debug.print("M1 benign-burst FINDING: tx[{d}] admitted but FEE-FAILED on real replay — H1's transfer-drain guess does NOT explain this traffic shape\n", .{idx});
            return e;
        };
        testing.expect(o.exec_ok) catch |e| {
            std.debug.print("M1 benign-burst FINDING: tx[{d}] admitted+fee-ok but the TRANSFER instruction itself failed\n", .{idx});
            return e;
        };
    }
    try testing.expect(!result.any_block_fatal);

    // VERDICT for this scenario: a genuinely benign, distinct-payer, no-drain-relationship burst does
    // NOT trip the transfer-drain gate gap. This supports — it does not itself prove, since the actual
    // 07-10 mempool contents were never captured — that IF the real 07-10 6-tx burst had this shape
    // (independent payers, no shared drain pattern), H1's specific "adversarial-only" mechanism would
    // NOT be what explains it; the adversarial-drain scenario above remains the confirmed, reachable
    // mechanism for the code's own documented "likely transfer-drain residual" comment. See the
    // forensics/ deliverable for the full plain-language statement this feeds into M2's fix-path choice.
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// M1 follow-up (same day, coordinator-directed): a "manual N-tx burst" test script is, operationally,
// almost always ONE keypair firing N sequential sends — not N independent wallets. The benign-burst
// scenario above (distinct payers) rules H1 OUT for THAT shape; it says nothing about the SAME-payer
// shape, which is a sequence of transfers from ONE account — structurally identical to the
// adversarial-drain scenario's tx-A-then-tx-B pattern, just arrived at by an ordinary/careless test
// script (a funding or fee-budgeting slip) instead of an attacker. This scenario tests that shape
// directly: 6 ORDINARY-SIZED transfers (0.05 SOL each — NOT a deliberate single-tx drain) from ONE
// payer P to 6 distinct recipients, sweeping (a) comfortably-funded P vs (b) P funded for only ~5 of
// the 6 sends (a plausible "forgot to budget for fees on a 6th tx" mistake, nothing adversarial about
// the CONSTRUCTION — no attacker chose to target P).
// ════════════════════════════════════════════════════════════════════════════════════════════════
test "M2 regression (named): same-payer benign-burst — gate now REFUSES tx 6 instead of admitting a block-fatal tx" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x66} ** 32;
    const parent_hash: Hash = [_]u8{0xCC} ** 32;
    const kp_p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xD1} ** 32);
    const payer_keys = [_][32]u8{kp_p.public_key.bytes};
    const amount: u64 = 50_000_000; // 0.05 SOL — an ORDINARY transfer size, not a deliberate drain

    var recipients: [6][32]u8 = undefined;
    var recipient_lamports: [6]u64 = undefined;
    var bufs: [6][512]u8 = undefined;
    var wires: [6][]const u8 = undefined;
    var txs: [6]ScenarioTx = undefined;
    var seed_byte: u8 = 0xE1;
    for (0..6) |idx| {
        recipients[idx] = [_]u8{seed_byte} ** 32;
        seed_byte += 1;
        recipient_lamports[idx] = 0;
        wires[idx] = buildTransferTx(kp_p, recipients[idx], bh, amount, &bufs[idx]);
        txs[idx] = .{ .recipient = recipients[idx], .amount = amount, .wire = wires[idx] };
    }

    // ── Variant (a): comfortably funded (3 SOL). 6×0.05 SOL + 6 fees (~300,030,000 lamports total) is
    //    a small fraction of that. Expect: clean, no block-fatal — the control case.
    {
        const payer_lamports = [_]u64{3_000_000_000};
        const result = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);
        for (result.outcomes[0..6], 0..) |o, idx| {
            testing.expect(o.admitted and o.fee_ok and o.exec_ok) catch |e| {
                std.debug.print("M1 same-payer-burst(a) FINDING: tx[{d}] unexpectedly failed on a comfortably-funded wallet\n", .{idx});
                return e;
            };
        }
        try testing.expect(!result.any_block_fatal);
    }

    // ── Variant (b): P funded with 250,027,500 lamports — enough for 5 of the 6 sends
    //    (5 × (50,000,000 + 5,000 fee) = 250,025,000) plus a 2,500-lamport slack, NOT enough for the
    //    6th tx's 5,000-lamport FEE. This is a funding/accounting slip (P sized for "5 sends", a 6th
    //    was added to the script) — nobody targeted P; the shape is entirely ordinary.
    {
        const payer_lamports = [_]u64{250_027_500};
        const result = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);

        // txs 1-5: ordinary, should succeed outright (funded exactly for them).
        for (result.outcomes[0..5], 0..) |o, idx| {
            testing.expect(o.admitted and o.fee_ok and o.exec_ok) catch |e| {
                std.debug.print("M1 same-payer-burst(b) FINDING: tx[{d}] (expected to succeed) did not\n", .{idx});
                return e;
            };
        }

        // tx 6: THE NAMED REGRESSION CASE, BEFORE→AFTER M2:
        //   BEFORE (M1, probe/txbearing-m1-gate-kat 5536d6d): admitted=true, fee_ok=false,
        //     any_block_fatal=true — fee-only bookkeeping against P's PARENT view (250,027,500
        //     comfortably affords 6 fees in isolation) had zero visibility into the 5 prior TRANSFERS
        //     that actually consumed P's balance, so the gate wrongly admitted tx 6 and real replay
        //     hit InsufficientFundsForFee -> BLOCK-FATAL — reachable by ORDINARY same-payer burst
        //     traffic, no attacker required.
        //   AFTER (M2, this commit): admitTxSeq applies each of txs 1-5's System::Transfer effects to
        //     P's tracked delta as they're admitted, so by the time tx 6 is evaluated the gate sees
        //     P's TRUE remaining balance (2,500 lamports) can't cover tx 6's 5,000-lamport fee and
        //     REFUSES it at admit time.
        testing.expect(!result.outcomes[5].admitted) catch |e| {
            std.debug.print("M2 REGRESSION: tx[5] was ADMITTED by the gate — the transfer-drain fix did not close this same-payer-burst case\n", .{});
            return e;
        };
        try testing.expect(!result.outcomes[5].fee_ok); // never replayed (not admitted) — default false
        try testing.expect(!result.any_block_fatal); // no block-fatal tx ever entered the produced block

        // VERDICT: this IS a same-payer, NO-ATTACKER, ordinary-sized-transfer burst — the exact shape
        // a manual multi-tx test script produces from one keypair — and M1 proved it went block-fatal
        // through the REAL gate (the former "adversarial-only" label at block_produce.zig, previously
        // :487-488, was too narrow: the mechanism needs only a same-payer SEQUENCE that exhausts the
        // payer partway through, hostile or not). M2's `SeqGateState`/`applyLamportEffects` extension
        // closes exactly this case: tx 6 is now correctly REFUSED, never reaching replay. See the M1
        // forensics deliverable for the updated verdict/confidence this raises for M2's priority.
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// PRODUCE-PARITY SUITE (2026-07-18) — the execute-once-and-record INTERIM (block_produce.zig
// admitTxSeq whitelist). RED→GREEN proof + generality (KAT-D) + normal-mempool clean pass (KAT-A).
//
// ROOT CAUSE #1 residual (forensics/txbearing-produce-parity-rootcause.md §2 D1b): M2's
// applyLamportEffects models ONLY System Transfer/CreateAccount. A tx that drains a later tx's
// fee-payer via a lamport-mover the gate CANNOT model (an unmodeled System discriminator, a non-System
// program, or an ALT/v0-loaded account) is admitted OPTIMISTICALLY → sequential replay finds the later
// tx NotLoaded → the cluster marks the whole block DEAD ([PRODUCE-PARITY-FAIL], a dead-block detector).
//
// THE INTERIM FIX (block_produce.zig admitTxSeq): a general WHITELIST — admit a tx ONLY if EVERY
// instruction is System-program with disc ∈ {Transfer, CreateAccount} AND every account index (incl.
// the program id) is a STATIC (non-ALT) key AND the tx is NOT versioned. Any other shape is REFUSED.
// The produced block is then a subset of the fully-modeled set → inclusion == execution for what it
// packs → it can only ever pack FEWER/EMPTY txs, NEVER a dead block. Throughput collapses to
// System-transfer traffic; that is the accepted interim cost until the durable produce-time executor.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Direct single-tx admission probe through the REAL live gate (admitTxSeq), against a fresh
/// frozen-parent view — exactly the decision `bankAdmitTxForBroadcast` (replay_stage.zig:1818-1853)
/// makes per tx, isolated so a containment KAT can assert admit/refuse per tx shape without the
/// blob-length coupling of the full produceSlotBytes matcher. `parent_lamports` funds the fee-payer
/// (signer[0]) comfortably; the ONLY thing under test is whether the whitelist admits the shape.
fn gateAdmits(a: std.mem.Allocator, wire: []const u8, blockhash_recent: [32]u8, parent_lamports: u64) !bool {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    var state = block_produce.SeqGateState{};
    defer state.deinit(a);
    const known = [_][32]u8{blockhash_recent};
    const fpv = block_produce.FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM_ID, .data_len = 0 };
    return block_produce.admitTxSeq(a, &state, parsed, wire, &known, fpv);
}

test "PRODUCE-PARITY RED→GREEN: unmodeled-disc drain of a shared fee-payer — dead block on the M2 gate, contained by the interim whitelist" {
    const a = testing.allocator;
    const kp_p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xF1} ** 32);
    const r1: [32]u8 = [_]u8{0xC1} ** 32;
    const r2: [32]u8 = [_]u8{0xC2} ** 32;
    const bh: [32]u8 = [_]u8{0x7A} ** 32;
    const parent_hash: Hash = [_]u8{0xDA} ** 32;

    // tx A: an UNMODELED System lamport-mover (disc 11, TransferWithSeed-proxy) that drains P to R1 —
    // applyLamportEffects `continue`s past it (lamportMoveAmount(11)==null), so the gate tracks ONLY
    // A's fee debit, NOT the 1,994,000-lamport drain. tx B: an ordinary Transfer from the SAME payer P.
    const payer_parent: u64 = 2_000_000;
    const amount_a: u64 = payer_parent - block_produce.LAMPORTS_PER_SIGNATURE - 1_000; // P left ~1,000
    const amount_b: u64 = 100;

    var buf_a: [512]u8 = undefined;
    var buf_b: [512]u8 = undefined;
    const wire_a = buildSystemDiscTx(kp_p, r1, bh, amount_a, 11, &buf_a); // UNMODELED disc
    const wire_b = buildTransferTx(kp_p, r2, bh, amount_b, &buf_b);

    const txs = [_]ScenarioTx{
        .{ .recipient = r1, .amount = amount_a, .wire = wire_a },
        .{ .recipient = r2, .amount = amount_b, .wire = wire_b },
    };
    const payer_keys = [_][32]u8{kp_p.public_key.bytes};
    const payer_lamports = [_]u64{payer_parent};
    const recipients = [_][32]u8{ r1, r2 };
    const recipient_lamports = [_]u64{ 0, 0 };

    const result = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);

    std.debug.print("[PRODUCE-PARITY-RED] txA(unmodeled-disc) admitted={} | txB admitted={} fee_ok={} | any_block_fatal(DEAD BLOCK)={}\n", .{ result.outcomes[0].admitted, result.outcomes[1].admitted, result.outcomes[1].fee_ok, result.any_block_fatal });

    // THE LOAD-BEARING ASSERTION, BEFORE→AFTER the interim whitelist:
    //   BEFORE (M2 gate only): tx A admitted (disc 11 skipped) AND tx B admitted (P's tracked delta =
    //     -fee only, gate blind to A's drain) → real replay drains P via A → tx B NotLoaded
    //     (InsufficientFundsForFee) → any_block_fatal = true → this test FAILS (dead block, the bug).
    //   AFTER  (whitelist): tx A REFUSED at admit (unmodeled disc 11), so P is never drained; tx B is a
    //     plain modeled Transfer → admitted, replays clean → any_block_fatal = false → this test PASSES.
    try testing.expect(!result.outcomes[0].admitted); // tx A (unmodeled disc) refused by the whitelist
    try testing.expect(result.outcomes[1].admitted); // tx B (plain Transfer) still admitted — not empty
    try testing.expect(result.outcomes[1].fee_ok); // and loads clean on replay (P not drained)
    try testing.expect(result.outcomes[1].exec_ok);
    try testing.expect(!result.any_block_fatal); // ← the produce/replay-agree assertion: NO dead block
}

test "PRODUCE-PARITY KAT-A: a normal mixed System-transfer mempool produces a clean, deterministic, dead-block-free slot" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x5A} ** 32;
    const parent_hash: Hash = [_]u8{0xAB} ** 32;
    const N = 5;
    var kps: [N]std.crypto.sign.Ed25519.KeyPair = undefined;
    var payer_keys: [N][32]u8 = undefined;
    var payer_lamports: [N]u64 = undefined;
    var recipients: [N][32]u8 = undefined;
    var recipient_lamports: [N]u64 = undefined;
    var bufs: [N][512]u8 = undefined;
    var txs: [N]ScenarioTx = undefined;
    var sb: u8 = 0x20;
    for (0..N) |i| {
        kps[i] = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{sb} ** 32);
        sb += 1;
        payer_keys[i] = kps[i].public_key.bytes;
        payer_lamports[i] = 100_000_000;
        recipients[i] = [_]u8{sb} ** 32;
        sb += 1;
        recipient_lamports[i] = 0;
        const amount: u64 = 1_000_000 * @as(u64, i + 1);
        const w = buildTransferTx(kps[i], recipients[i], bh, amount, &bufs[i]);
        txs[i] = .{ .recipient = recipients[i], .amount = amount, .wire = w };
    }

    const r1 = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);
    const r2 = try runGatedScenario(a, parent_hash, bh, &payer_keys, &payer_lamports, &recipients, &recipient_lamports, &txs);

    // Every ordinary modeled transfer is admitted (whitelist does NOT over-refuse valid System txs) and
    // loads clean; no dead block; and the frozen bank_hash is deterministic across two produce→replays.
    for (r1.outcomes[0..N]) |o| {
        try testing.expect(o.admitted and o.fee_ok and o.exec_ok);
    }
    try testing.expect(!r1.any_block_fatal);
    try testing.expectEqualSlices(u8, &r1.bank_hash, &r2.bank_hash);
}

test "PRODUCE-PARITY KAT-D: the whitelist REFUSES every un-modelable carrier class (generality, not a per-disc patch)" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x6B} ** 32;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x9A} ** 32);
    const recipient: [32]u8 = [_]u8{0xE7} ** 32;
    const parent: u64 = 1_000_000_000; // funded so the ONLY reason to refuse is un-modelability
    var buf: [512]u8 = undefined;

    // Control: a plain modeled System Transfer is ADMITTED.
    {
        const w = buildTransferTx(kp, recipient, bh, 1_000, &buf);
        try testing.expect(try gateAdmits(a, w, bh, parent));
    }
    // Carrier 1 — unmodeled System discriminator (TransferWithSeed-proxy, disc 11): REFUSED.
    {
        const w = buildSystemDiscTx(kp, recipient, bh, 1_000, 11, &buf);
        try testing.expect(!(try gateAdmits(a, w, bh, parent)));
    }
    // Carrier 1b — another unmodeled System discriminator (Assign = 1): REFUSED (class, not one value).
    {
        const w = buildSystemDiscTx(kp, recipient, bh, 1_000, 1, &buf);
        try testing.expect(!(try gateAdmits(a, w, bh, parent)));
    }
    // Carrier 2 — non-System program invocation (a synthetic BPF program that could CPI-drain): REFUSED.
    {
        const prog: [32]u8 = [_]u8{0x42} ** 32;
        const w = buildNonSystemProgramTx(kp, recipient, prog, bh, &buf);
        try testing.expect(!(try gateAdmits(a, w, bh, parent)));
    }
    // Carrier 3 — v0 versioned tx (the ALT carrier): REFUSED regardless of instruction contents.
    {
        const w = buildV0TransferTx(kp, recipient, bh, 1_000, &buf);
        try testing.expect(!(try gateAdmits(a, w, bh, parent)));
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// CROSS-BLOCK SIGNATURE DEDUP (2026-07-19, P1) — the ONE dead-block channel the produce-parity
// whitelist does NOT close. A FULLY-MODELED System transfer whose FIRST signature duplicates one
// committed within the recent window (≤150 slots) is admitted by admitTxSeq (the tx itself is
// perfectly loadable in isolation) → the cluster's status cache rejects it AlreadyProcessed →
// NotLoaded → the whole block is marked dead. Closed by RecentSigCache consulted in the composed,
// TEST-ROOTABLE produce-admit unit block_produce.admitTxSeqBroadcast (the live path
// replay_stage.zig bankAdmitTxForBroadcast delegates to it). Populated on the replay commit path
// (replay_stage.zig:9441) keyed on the wire's post-count signature bytes — the SAME bytes the query
// keys on (asserted below), so a live record and a live query hit the same map entry.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// The 64-byte first signature as the COMMIT path records it: the bytes immediately after the wire's
/// compact-u16 signature count (replay_stage.zig `tx_data[first_sig_off..][0..64]`). These test txs
/// carry exactly 1 signature ⇒ a single-byte count (0x01) ⇒ the signature is wire[1..65]. Kept
/// separate from `parsed.signatures[0]` on purpose so the KAT can assert the two representations are
/// byte-identical (else production would record one key and query another, silently no-op'ing dedup).
fn wireFirstSig(wire: []const u8) *const [64]u8 {
    std.debug.assert(wire[0] == 1); // single-signature compact-u16 count for these builders
    return wire[1..65];
}

/// Composed produce-admit probe: cross-block dedup (recent_sigs) THEN the sequential gate — exactly
/// the decision bankAdmitTxForBroadcast makes per tx. `recent_sigs`==null reproduces the pre-dedup
/// (status-cache-off) behavior; a populated cache arms the AlreadyProcessed refusal.
fn dedupAdmits(a: std.mem.Allocator, wire: []const u8, blockhash_recent: [32]u8, parent_lamports: u64, recent_sigs: ?*const block_produce.RecentSigCache, producing_slot: u64) !bool {
    const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    var state = block_produce.SeqGateState{};
    defer state.deinit(a);
    const known = [_][32]u8{blockhash_recent};
    const fpv = block_produce.FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM_ID, .data_len = 0 };
    return block_produce.admitTxSeqBroadcast(a, &state, parsed, wire, &known, fpv, recent_sigs, producing_slot);
}

test "CROSS-BLOCK DEDUP RED→GREEN: a duplicate-signature System transfer is ADMITTED without the cache (dead block) and REFUSED with it" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x3D} ** 32);
    const recipient: [32]u8 = [_]u8{0xC9} ** 32;
    const bh: [32]u8 = [_]u8{0x8B} ** 32;
    const parent: u64 = 1_000_000_000; // funded so the ONLY possible refusal reason is dedup
    const committed_slot: u64 = 500_000;
    var buf: [512]u8 = undefined;

    // A fully-modeled System transfer — passes the whitelist + fee gate in isolation (it is loadable).
    const w = buildTransferTx(kp, recipient, bh, 1_000, &buf);

    // Advisor item 1: the key the COMMIT path records (wire post-count bytes) MUST equal the key the
    // QUERY path (parsed.signatures[0]) uses — else live dedup silently no-ops. Tie them explicitly.
    {
        var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = try tx_ingest.parse(w, &ssig, &skey);
        try testing.expectEqualSlices(u8, &parsed.signatures[0], wireFirstSig(w));
    }

    // Populate the cache the way the live replay commit path does: from the wire signature bytes.
    var cache = block_produce.RecentSigCache{};
    defer cache.deinit(a);
    cache.record(a, wireFirstSig(w), committed_slot);

    // RED (the dead-block channel): with NO cache wired, the duplicate is ADMITTED — it would be packed
    // and the cluster would mark the block dead AlreadyProcessed. This is the pre-P1 status-cache-off
    // behavior, captured inline so the fix's load-bearing variable is isolated to the cache argument.
    try testing.expect(try dedupAdmits(a, w, bh, parent, null, committed_slot));

    // GREEN: same tx, same gate, cache wired + producing within the 150-slot window ⇒ REFUSED.
    try testing.expect(!(try dedupAdmits(a, w, bh, parent, &cache, committed_slot + 100)));
    // Boundary (inclusive): exactly 150 slots later is still AlreadyProcessed ⇒ REFUSED.
    try testing.expect(!(try dedupAdmits(a, w, bh, parent, &cache, committed_slot + block_produce.RecentSigCache.MAX_RECENT_SLOTS)));
    // Outside the window (>150 slots later): the blockhash-validity window has passed ⇒ ADMITTED again
    // (dedup does not over-refuse a stale entry — it self-limits, matching Agave MAX_PROCESSING_AGE).
    try testing.expect(try dedupAdmits(a, w, bh, parent, &cache, committed_slot + block_produce.RecentSigCache.MAX_RECENT_SLOTS + 1));
}

test "CROSS-BLOCK DEDUP: the cache refuses ONLY the duplicated signature, never a distinct tx (no over-refusal)" {
    const a = testing.allocator;
    const kp1 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const kp2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    const recipient: [32]u8 = [_]u8{0xD4} ** 32;
    const bh: [32]u8 = [_]u8{0x77} ** 32;
    const parent: u64 = 1_000_000_000;
    const slot: u64 = 900_000;
    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;

    const w1 = buildTransferTx(kp1, recipient, bh, 1_000, &buf1); // this one's sig gets committed
    const w2 = buildTransferTx(kp2, recipient, bh, 1_000, &buf2); // a DISTINCT tx (different signer/sig)

    var cache = block_produce.RecentSigCache{};
    defer cache.deinit(a);
    cache.record(a, wireFirstSig(w1), slot);

    // The recorded tx is refused; the distinct tx (different signature) is unaffected and admitted.
    try testing.expect(!(try dedupAdmits(a, w1, bh, parent, &cache, slot))); // duplicate → refused
    try testing.expect(try dedupAdmits(a, w2, bh, parent, &cache, slot)); // distinct → admitted
    // Sanity: the two txs really do have different first signatures (else the test proves nothing).
    try testing.expect(!std.mem.eql(u8, wireFirstSig(w1), wireFirstSig(w2)));
}
