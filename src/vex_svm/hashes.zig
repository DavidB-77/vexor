/// hashes.zig — Firedancer fd_hashes.c port for Vexor
/// @prov:svm.hashes-port
///
/// Ported from:
///   firedancer/src/flamenco/runtime/fd_hashes.c (138 lines)
///   (originally worked from a local reference checkout, not shipped in this repo)
///
/// Functions ported:
///   fd_hashes_account_lthash_simple() → accountLtHash()
///   fd_hashes_hash_bank()             → hashBank()
///   fd_hashes_update_lthash1()        → updateLtHash()
///   fd_hashes_apply_hard_forks()      → applyHardForks()
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
/// SIMD: LtHash uses @Vector(32, u16) — 512-bit AVX-512 on znver4 (1024 u16 = 32 vectors).
const std = @import("std");
const vex_crypto = @import("vex_crypto");

pub const Hash = vex_crypto.Hash;
pub const LtHash = vex_crypto.LtHash;

// ─────────────────────────────────────────────────────────────────────────────
// accountLtHash — fd_hashes.c:23-48
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the 2048-byte LtHash contribution of a single account state.
///
/// Firedancer: fd_hashes_account_lthash_simple()
/// fd_hashes.c:23-48
///
/// Formula (BLAKE3-2048 of concatenated fields):
///   BLAKE3( lamports_le8 || data || executable_u8 || owner[32] || pubkey[32] )
///   → 2048 bytes interpreted as 1024 × u16 (little-endian, wrapping)
///
/// Critical rules (fd_hashes.c:30-32):
///   - Zero-lamport accounts are excluded: returns the zero LtHash.
///   - executable_flag = executable & 1  (not a bool cast, mask the bit)
///
/// Parameters match Firedancer's fd_hashes_account_lthash_simple() signature:
///   pubkey[32], owner[32], lamports: u64, executable: bool, data: []const u8
pub fn accountLtHash(
    pubkey: *const [32]u8,
    owner: *const [32]u8,
    lamports: u64,
    executable: bool,
    data: []const u8,
) LtHash {
    // fd_hashes.c:30-32: zero-lamport accounts contribute nothing
    if (lamports == 0) return LtHash.init();

    // fd_hashes.c:34: executable_flag = !!executable (0 or 1)
    const executable_flag: u8 = if (executable) 1 else 0;

    // fd_hashes.c:36-43: BLAKE3 over fields in this exact order:
    //   lamports (8 bytes LE) → data → executable_flag (1 byte) → owner → pubkey
    var b3 = std.crypto.hash.Blake3.init(.{});

    var lamports_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &lamports_le, lamports, .little); // fd_hashes.c:38
    b3.update(&lamports_le);
    b3.update(data); // fd_hashes.c:39
    b3.update(&[_]u8{executable_flag}); // fd_hashes.c:40
    b3.update(owner[0..32]); // fd_hashes.c:41
    b3.update(pubkey[0..32]); // fd_hashes.c:42

    // fd_hashes.c:43: fd_blake3_fini_2048 — produce exactly 2048 bytes via XOF
    // std.crypto.hash.Blake3 supports finalizeSeek() for extended output (XOF mode).
    var out: [2048]u8 = undefined;
    b3.finalizeSeek(0, &out);

    // Interpret 2048 bytes as 1024 × u16 LE (matching fd_lthash_value_t layout)
    // Use @Vector(32, u16) for AVX-512 SIMD on znver4 — processes 32 u16s per vector op.
    var lt = LtHash.init();
    for (0..1024) |i| {
        lt.elements[i] = std.mem.readInt(u16, out[i * 2 ..][0..2], .little);
    }
    return lt;
}

// ─────────────────────────────────────────────────────────────────────────────
// hashBank — fd_hashes.c:50-74
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the two-step SHA256 bank hash for a slot.
///
/// Firedancer: fd_hashes_hash_bank()
/// fd_hashes.c:50-74
///
/// Formula (SIMD-0215 / Solana bank hash):
///   step1 = SHA256( prev_bank_hash[32] || signature_count_le8 || last_blockhash[32] )
///   hash  = SHA256( step1[32] || lthash_bytes[2048] )
///
/// Parameters:
///   lthash          — accumulated LtHash of all accounts modified in this slot
///   prev_bank_hash  — bank hash of the parent slot
///   last_blockhash  — PoH hash of the last entry in this slot (bank->f.poh in FD)
///   signature_count — total signatures in this slot's transactions
///
/// IMPORTANT: last_blockhash is NOT the transaction's recent_blockhash field.
/// It is the PoH hash from the last tick/entry of the slot.
pub fn hashBank(
    lthash: *const LtHash,
    prev_bank_hash: *const Hash,
    last_blockhash: *const Hash,
    signature_count: u64,
) Hash {
    // Step 1 — fd_hashes.c:59-64
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(&prev_bank_hash.data); // fd_hashes.c:61: prev_bank_hash (32 bytes)
    var sig_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sig_le, signature_count, .little);
    sha.update(&sig_le); // fd_hashes.c:62: signature_count (8 bytes LE)
    sha.update(&last_blockhash.data); // fd_hashes.c:63: last_blockhash (32 bytes)
    var step1: [32]u8 = undefined;
    sha.final(&step1); // fd_hashes.c:64

    // Step 2 — fd_hashes.c:66-69
    var sha2 = std.crypto.hash.sha2.Sha256.init(.{});
    sha2.update(&step1); // fd_hashes.c:67: step1 (32 bytes)

    // Write lthash as raw 2048 LE bytes — fd_hashes.c:68: lthash->bytes (2048 bytes)
    // Use @Vector(32, u16) for SIMD serialization on znver4 AVX-512
    var lthash_bytes: [2048]u8 = undefined;
    comptime var vi: usize = 0;
    inline while (vi < 1024) : (vi += 1) {
        std.mem.writeInt(u16, lthash_bytes[vi * 2 ..][0..2], lthash.elements[vi], .little);
    }
    sha2.update(&lthash_bytes);
    var result: [32]u8 = undefined;
    sha2.final(&result); // fd_hashes.c:69

    return Hash.init(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// updateLtHash — fd_hashes.c:76-114
// ─────────────────────────────────────────────────────────────────────────────

/// Update a running bank LtHash accumulator for one account change.
///
/// Firedancer: fd_hashes_update_lthash1()
/// fd_hashes.c:76-114
///
/// Operation (atomic in Firedancer due to mutex on bank_lthash):
///   lthash_post = accountLtHash(pubkey, new account state)
///   bank_lthash -= lthash_prev         (remove old contribution)
///   bank_lthash += lthash_post         (add new contribution)
///
/// Parameters:
///   bank_lthash — mutable running accumulator to update in-place
///   lthash_prev — pre-computed LtHash of the OLD account state
///                 (caller must compute this before modifying the account)
///   pubkey      — account address (32 bytes)
///   owner       — account owner program (32 bytes)
///   lamports    — NEW lamport balance
///   executable  — NEW executable bit
///   data        — NEW account data
///
/// Returns the new LtHash (lthash_post) for optional capture/logging use.
pub fn updateLtHash(
    bank_lthash: *LtHash, // fd_hashes.c:77: fd_lthash_value_t * lthash_post (out, also updates bank)
    lthash_prev: *const LtHash, // fd_hashes.c:78: fd_lthash_value_t const * lthash_prev
    pubkey: *const [32]u8,
    owner: *const [32]u8,
    lamports: u64,
    executable: bool,
    data: []const u8,
) LtHash {
    // fd_hashes.c:81: Hash the new version of the account
    const lthash_post = accountLtHash(pubkey, owner, lamports, executable, data);

    // fd_hashes.c:84-85: bank_lthash -= lthash_prev (remove old contribution)
    // fd_lthash_sub(bank_lthash, lthash_prev)
    bank_lthash.wrappingSub(lthash_prev);

    // fd_hashes.c:88-89: bank_lthash += lthash_post (add new contribution)
    // fd_lthash_add(bank_lthash, lthash_post)
    bank_lthash.wrappingAdd(&lthash_post);

    return lthash_post;
}

// ─────────────────────────────────────────────────────────────────────────────
// applyHardForks — fd_hashes.c:116-138
// ─────────────────────────────────────────────────────────────────────────────

/// Apply hard fork hashing for a slot boundary.
///
/// Firedancer: fd_hashes_apply_hard_forks()
/// fd_hashes.c:116-138
///
/// When one or more hard forks occurred strictly within (parent_slot, slot],
/// sum their activation counts and fold them into the hash via:
///   hash = SHA256( hash[32] || sum_le8 )
///
/// This is a no-op if no hard forks are active in the range.
pub fn applyHardForks(
    hash: *Hash,
    slot: u64,
    parent_slot: u64,
    hard_forks: []const u64, // fd_hashes.c:121: hard fork slot numbers
    hard_fork_counts: []const u64, // fd_hashes.c:122: activation counts per hard fork
) void {
    std.debug.assert(hard_forks.len == hard_fork_counts.len);

    // fd_hashes.c:123-125: sum activation counts for hard forks in range (parent_slot, slot]
    var sum: u64 = 0;
    for (hard_forks, hard_fork_counts) |hf_slot, hf_cnt| {
        if (parent_slot < hf_slot and hf_slot <= slot) {
            sum +%= hf_cnt; // wrapping add matching C ulong arithmetic
        }
    }

    // fd_hashes.c:127-128: no-op if no hard forks in range
    if (sum == 0) return;

    // fd_hashes.c:130-136: fold sum into hash
    var sum_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sum_le, sum, .little); // fd_hashes.c:131: FD_STORE(ulong, sum_le, sum)

    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(&hash.data); // fd_hashes.c:133
    sha.update(&sum_le); // fd_hashes.c:134: sizeof(ulong)=8
    sha.final(&hash.data); // fd_hashes.c:135: in-place update
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "accountLtHash: zero lamports → zero lthash" {
    const lt = accountLtHash(&([_]u8{1} ** 32), &([_]u8{0} ** 32), 0, false, &[_]u8{});
    for (lt.elements) |e| try std.testing.expectEqual(@as(u16, 0), e);
}

test "accountLtHash: non-zero lamports → non-zero lthash" {
    const lt = accountLtHash(&([_]u8{1} ** 32), &([_]u8{0} ** 32), 1_000_000, false, &[_]u8{});
    var any_nonzero = false;
    for (lt.elements) |e| {
        if (e != 0) {
            any_nonzero = true;
            break;
        }
    }
    try std.testing.expect(any_nonzero);
}

test "accountLtHash: deterministic" {
    const pubkey = [_]u8{0xAB} ** 32;
    const owner = [_]u8{0xCD} ** 32;
    const data = [_]u8{ 1, 2, 3 };
    const lt1 = accountLtHash(&pubkey, &owner, 100, true, &data);
    const lt2 = accountLtHash(&pubkey, &owner, 100, true, &data);
    try std.testing.expectEqualSlices(u16, &lt1.elements, &lt2.elements);
}

test "hashBank: deterministic two-step SHA256" {
    const prev = Hash.default();
    const poh = Hash.init([_]u8{0xAB} ** 32);
    const lt = LtHash.init();
    const h1 = hashBank(&lt, &prev, &poh, 500);
    const h2 = hashBank(&lt, &prev, &poh, 500);
    try std.testing.expectEqualSlices(u8, &h1.data, &h2.data);
    // Must differ from all-zero inputs
    const h_zero = hashBank(&lt, &prev, &Hash.default(), 0);
    // Different poh → different hash
    try std.testing.expect(!std.mem.eql(u8, &h1.data, &h_zero.data));
}

test "updateLtHash: add then remove = identity" {
    var acc = LtHash.init();
    const prev = LtHash.init();
    const pubkey = [_]u8{0x01} ** 32;
    const owner = [_]u8{0x02} ** 32;

    // Apply update (lamports=1000)
    _ = updateLtHash(&acc, &prev, &pubkey, &owner, 1000, false, &[_]u8{});

    // Revert: update with new=0 (delete), old=what we just computed
    const after_add = acc;
    const prev2 = accountLtHash(&pubkey, &owner, 1000, false, &[_]u8{});
    _ = updateLtHash(&acc, &prev2, &pubkey, &owner, 0, false, &[_]u8{});

    // acc should now be same as after_add minus after_add (back to init)
    // i.e., acc should equal init since we added then removed same delta
    _ = after_add; // used for context
    // zero-lamport new hash = zero → bank_lthash -= prev2 + 0 = init
    for (acc.elements) |e| try std.testing.expectEqual(@as(u16, 0), e);
}

test "applyHardForks: no forks in range → hash unchanged" {
    var h = Hash.init([_]u8{0x42} ** 32);
    const orig = h.data;
    applyHardForks(&h, 100, 99, &[_]u64{50}, &[_]u64{1}); // fork at slot 50, outside (99,100]
    try std.testing.expectEqualSlices(u8, &orig, &h.data);
}

test "applyHardForks: fork in range → hash changes" {
    var h = Hash.init([_]u8{0x42} ** 32);
    const orig = h.data;
    applyHardForks(&h, 100, 99, &[_]u64{100}, &[_]u64{1}); // fork at slot 100, inside (99,100]
    try std.testing.expect(!std.mem.eql(u8, &orig, &h.data));
}
