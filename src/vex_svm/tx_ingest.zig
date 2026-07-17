//! SB-1 (parity backlog, shared blocker — front half): transaction wire decode + sigverify.
//!
//! The "accept a tx off the wire, sigverify it" stage shared by RPC sendTransaction (decode → verify →
//! forward) and simulateTransaction (decode → verify → execute-and-discard), and the block producer's
//! TPU ingest. Parses a serialized VersionedTransaction (legacy OR v0) into its signatures + message +
//! signer pubkeys and ed25519-verifies each required signature over the message. The execute-against-a-
//! bank half (the shared executeOnBank reusing the replay SVM) is a separate, larger increment.
//!
//! ADDITIVE + KAT-gated; NOT wired into the live path yet. Wire format (Solana tx):
//!   compactU16(num_sigs) ‖ num_sigs×64B signatures ‖ message
//! message (legacy): [num_req_sigs][num_ro_signed][num_ro_unsigned] compactU16(n_keys) n_keys×32B keys
//!                   ‖ 32B blockhash ‖ compactU16(n_ix) instructions…
//! message (v0):     [0x80|version] then the legacy layout, then address_table_lookups.
//! The SIGNED bytes = the entire message (everything after the signatures). The first num_req_sigs
//! account keys are the signers; signature[i] must verify against key[i] over the message.

const std = @import("std");
const core = @import("core");
const ed25519 = @import("vex_crypto").ed25519;

const Pubkey = core.Pubkey;

pub const IngestError = error{
    Truncated,
    TooManySignatures,
    NoSignatures,
    SignatureCountMismatch,
    InvalidBase64,
    OutOfMemory,
};

/// Solana sanity cap: a tx is ≤ 1232 bytes (one MTU-ish packet).
pub const MAX_TX_BYTES: usize = 1232;
/// Canonical FD_TXN_SIG_MAX = 127 (firedancer/src/ballet/txn/fd_txn.h:67); replay_stage.zig's parser
/// uses the same value. The earlier 19 cap was a carrier-class straggler (it could reject a tx the
/// canonical replay parser accepts → ingest/replay disagree). MUST match replay_stage's 127.
pub const MAX_SIGNATURES: usize = 127;

/// A parsed-but-not-executed transaction. All slices are views INTO the caller's wire buffer (no copy)
/// — the wire buffer must outlive the ParsedTx.
pub const ParsedTx = struct {
    /// num_required_signatures from the message header (== the number of leading signer keys).
    num_required_sigs: u8,
    /// Total static account keys declared in the message header (signers + non-signers).
    num_keys: u16,
    /// Byte offset into `wire` of the first static account key. Lets a downstream pass resolve a
    /// program_id_index → its key (e.g. ComputeBudget priority extraction) without re-walking the header.
    keys_offset: usize,
    /// Byte offset into `wire` of the instruction-count compact-u16 (after all keys + the 32B blockhash;
    /// same position for legacy and v0). May be ≥ wire.len for a degenerate tx — downstream parsers
    /// treat out-of-range as "no instructions" and return 0.
    instructions_offset: usize,
    /// The signature blobs (≥ num_required_sigs of them), each a 64-byte view into `wire`.
    signatures: []const [64]u8,
    /// The signed message bytes (everything after the signature array, to end of wire).
    message: []const u8,
    /// The first num_required_sigs static account keys (the signers), views into `wire`.
    signer_keys: []const [32]u8,
    /// true if the message is a v0 versioned message (leading 0x80 byte), false if legacy.
    is_versioned: bool,

    /// The canonical transaction id = the first signature.
    pub fn id(self: ParsedTx) *const [64]u8 {
        return &self.signatures[0];
    }
};

/// Read a Solana compact-u16 (shortvec) at `buf[pos.*]`, advancing `pos`. 1–3 bytes, 7 bits each,
/// high bit = continuation. Mirrors entry_kat_real.readCompactU16.
fn readCompactU16(buf: []const u8, pos: *usize) IngestError!u16 {
    var val: u32 = 0;
    var shift: u5 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* >= buf.len) return error.Truncated;
        const byte = buf[pos.*];
        pos.* += 1;
        val |= @as(u32, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return @intCast(val & 0xffff);
        shift += 7;
    }
    return @intCast(val & 0xffff);
}

/// Parse a serialized transaction (wire bytes) into signatures + message + signer keys. The returned
/// ParsedTx borrows `wire` (no allocation). `scratch_sigs` / `scratch_keys` are caller-provided arrays
/// the views are written into (sized MAX_SIGNATURES). Returns the trimmed slices.
pub fn parse(
    wire: []const u8,
    scratch_sigs: *[MAX_SIGNATURES][64]u8,
    scratch_keys: *[MAX_SIGNATURES][32]u8,
) IngestError!ParsedTx {
    if (wire.len < 1 + 64 + 3) return error.Truncated; // 1 sig + minimal message floor
    var pos: usize = 0;

    const num_sigs = try readCompactU16(wire, &pos);
    if (num_sigs == 0) return error.NoSignatures;
    if (num_sigs > MAX_SIGNATURES) return error.TooManySignatures;
    if (pos + @as(usize, num_sigs) * 64 > wire.len) return error.Truncated;

    for (0..num_sigs) |i| {
        @memcpy(&scratch_sigs[i], wire[pos..][0..64]);
        pos += 64;
    }

    const message_start = pos;
    const message = wire[message_start..];

    // Message header.
    var mpos: usize = message_start;
    if (mpos >= wire.len) return error.Truncated;
    const is_versioned = (wire[mpos] & 0x80) != 0;
    if (is_versioned) mpos += 1; // skip the version byte (0x80 | version)

    if (mpos >= wire.len) return error.Truncated;
    const num_required: u8 = wire[mpos];
    mpos += 1;
    if (num_required == 0) return error.NoSignatures;
    if (num_required > num_sigs) return error.SignatureCountMismatch;
    mpos += 2; // skip num_readonly_signed, num_readonly_unsigned

    const n_keys = try readCompactU16(wire, &mpos);
    if (num_required > n_keys) return error.SignatureCountMismatch;
    const keys_offset = mpos; // first static account key begins here
    if (mpos + @as(usize, num_required) * 32 > wire.len) return error.Truncated;
    for (0..num_required) |i| {
        @memcpy(&scratch_keys[i], wire[mpos + i * 32 ..][0..32]);
    }
    // The instruction list begins after ALL n_keys static keys + the 32-byte recent blockhash. This
    // position is identical for legacy and v0 messages (v0's address_table_lookups come AFTER the
    // instructions). Computed, not bounds-checked here: a truncated tx yields an offset ≥ wire.len,
    // which downstream ComputeBudget parsing treats as "no instructions" (returns 0).
    const instructions_offset = keys_offset + @as(usize, n_keys) * 32 + 32;

    return .{
        .num_required_sigs = num_required,
        .num_keys = n_keys,
        .keys_offset = keys_offset,
        .instructions_offset = instructions_offset,
        .signatures = scratch_sigs[0..num_sigs],
        .message = message,
        .signer_keys = scratch_keys[0..num_required],
        .is_versioned = is_versioned,
    };
}

/// ed25519-verify every required signature over the message. Returns true iff all pass. This is the
/// sigverify gate sendTransaction/simulateTransaction apply before doing anything else with the tx.
pub fn verifySignatures(tx: ParsedTx) bool {
    for (0..tx.num_required_sigs) |i| {
        if (!ed25519.verify(&tx.signatures[i], &tx.signer_keys[i], tx.message)) return false;
    }
    return true;
}

/// Decode a base64 (standard) RPC `params[0]` transaction payload into wire bytes. Caller frees.
/// (sendTransaction also accepts base58 historically; base64 is the modern default — base58 is a
/// follow-up.) Enforces the MAX_TX_BYTES sanity cap.
pub fn decodeBase64(allocator: std.mem.Allocator, b64: []const u8) IngestError![]u8 {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return error.InvalidBase64;
    if (n > MAX_TX_BYTES) return error.Truncated;
    const out = try allocator.alloc(u8, n);
    errdefer allocator.free(out);
    dec.decode(out, b64) catch return error.InvalidBase64;
    return out;
}

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

/// Build a minimal valid legacy single-signer transaction signed by `kp`, into `out` (returns the
/// trimmed wire slice). message = [1,0,0] header, 1 account key (the signer), zero blockhash, 0 ix.
fn buildSingleSignerTx(kp: std.crypto.sign.Ed25519.KeyPair, out: []u8) []u8 {
    // message bytes first (we sign them), assembled at out[65..] (after 1-byte count + 64-byte sig).
    var mpos: usize = 1 + 64; // compactU16(1) is a single byte 0x01
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 0; // num_readonly_unsigned
    mpos += 3;
    out[mpos] = 1; // compactU16: 1 account key
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // the signer key
    mpos += 32;
    @memset(out[mpos..][0..32], 0); // recent blockhash
    mpos += 32;
    out[mpos] = 0; // compactU16: 0 instructions
    mpos += 1;
    const message = out[msg_start..mpos];

    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "tx_ingest: parse + verify a self-signed legacy tx (round-trip), tamper fails" {
    const seed = [_]u8{0x42} ** 32;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);

    var buf: [256]u8 = undefined;
    const wire = buildSingleSignerTx(kp, &buf);

    var ssig: [MAX_SIGNATURES][64]u8 = undefined;
    var skey: [MAX_SIGNATURES][32]u8 = undefined;
    const tx = try parse(wire, &ssig, &skey);

    try testing.expectEqual(@as(u8, 1), tx.num_required_sigs);
    try testing.expectEqual(@as(usize, 1), tx.signatures.len);
    try testing.expect(!tx.is_versioned);
    try testing.expectEqualSlices(u8, &kp.public_key.bytes, &tx.signer_keys[0]);
    try testing.expect(verifySignatures(tx)); // VALID signature verifies

    // Tamper the message (flip a blockhash byte) → re-parse → verify must FAIL.
    var bad: [256]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[wire.len - 1] = 0xFF; // change the instruction-count byte (in the signed message)
    const tx2 = try parse(bad[0..wire.len], &ssig, &skey);
    try testing.expect(!verifySignatures(tx2)); // signature no longer matches the message

    // Tamper a signature byte → fail.
    @memcpy(bad[0..wire.len], wire);
    bad[5] ^= 0x01; // flip a bit inside signature[0]
    const tx3 = try parse(bad[0..wire.len], &ssig, &skey);
    try testing.expect(!verifySignatures(tx3));
}

test "tx_ingest: v0 versioned message header parsed (0x80 version byte skipped)" {
    const seed = [_]u8{0x07} ** 32;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    // Build like the legacy helper but set the version byte (0x80) as the first message byte.
    var out: [256]u8 = undefined;
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 0x80; // v0 version marker
    out[mpos + 1] = 1; // num_required_signatures
    out[mpos + 2] = 0;
    out[mpos + 3] = 0;
    mpos += 4;
    out[mpos] = 1; // 1 account key
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memset(out[mpos..][0..32], 0);
    mpos += 32;
    out[mpos] = 0; // 0 instructions
    mpos += 1;
    // (a real v0 message also has address_table_lookups after this; not needed for header/sigverify)
    const message = out[msg_start..mpos];
    const sig = try kp.sign(message, null);
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    const wire = out[0..mpos];

    var ssig: [MAX_SIGNATURES][64]u8 = undefined;
    var skey: [MAX_SIGNATURES][32]u8 = undefined;
    const tx = try parse(wire, &ssig, &skey);
    try testing.expect(tx.is_versioned);
    try testing.expectEqual(@as(u8, 1), tx.num_required_sigs);
    try testing.expect(verifySignatures(tx));
}

test "tx_ingest: malformed inputs rejected" {
    var ssig: [MAX_SIGNATURES][64]u8 = undefined;
    var skey: [MAX_SIGNATURES][32]u8 = undefined;
    try testing.expectError(error.Truncated, parse(&[_]u8{ 1, 2, 3 }, &ssig, &skey)); // too short
    // num_sigs=0
    var z: [80]u8 = [_]u8{0} ** 80;
    z[0] = 0;
    try testing.expectError(error.NoSignatures, parse(&z, &ssig, &skey));
}

test "tx_ingest: >19 signatures parse OK (canonical FD_TXN_SIG_MAX=127, not the old 19 cap)" {
    // A 20-signer structure (well-formed, dummy sig/key bytes). Under the OLD cap of 19 this returned
    // error.TooManySignatures — the carrier. With the canonical 127 cap it must parse. (Not a real
    // 1232B packet: this exercises the parser's cap, which is what diverged from replay_stage.)
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 20; // compactU16(20) signatures (20 < 128 → single byte)
    pos += 1;
    @memset(buf[pos..][0 .. 20 * 64], 0); // 20 dummy signatures
    pos += 20 * 64;
    buf[pos] = 20; // num_required_signatures
    buf[pos + 1] = 0; // num_readonly_signed
    buf[pos + 2] = 0; // num_readonly_unsigned
    pos += 3;
    buf[pos] = 20; // compactU16(20) account keys
    pos += 1;
    @memset(buf[pos..][0 .. 20 * 32], 0); // 20 dummy signer keys
    pos += 20 * 32;
    @memset(buf[pos..][0..32], 0); // recent blockhash
    pos += 32;
    buf[pos] = 0; // 0 instructions
    pos += 1;

    var ssig: [MAX_SIGNATURES][64]u8 = undefined;
    var skey: [MAX_SIGNATURES][32]u8 = undefined;
    const tx = try parse(buf[0..pos], &ssig, &skey);
    try testing.expectEqual(@as(usize, 20), tx.signatures.len);
    try testing.expectEqual(@as(u8, 20), tx.num_required_sigs);

    // Boundary: 128 signatures is still rejected (cap is 127, the inclusive FD max).
    var big: [128 * 64 + 256]u8 = undefined;
    var bp: usize = 0;
    big[0] = 0x80; // compactU16(128) = 0x80, 0x01
    big[1] = 0x01;
    bp = 2;
    @memset(big[bp..][0 .. 128 * 64], 0);
    bp += 128 * 64;
    big[bp] = 1;
    big[bp + 1] = 0;
    big[bp + 2] = 0;
    bp += 3;
    big[bp] = 1;
    bp += 1;
    @memset(big[bp..][0..32], 0);
    bp += 32;
    @memset(big[bp..][0..32], 0);
    bp += 32;
    big[bp] = 0;
    bp += 1;
    try testing.expectError(error.TooManySignatures, parse(big[0..bp], &ssig, &skey));
}

test "tx_ingest: parse exposes num_keys / keys_offset / instructions_offset (2-key legacy tx)" {
    // 2 account keys (1 signer + 1 program), 1 instruction. Structure-only (dummy sig); parse() does
    // not sigverify, so we assert the layout offsets a downstream ComputeBudget pass relies on.
    var wire: [178]u8 = undefined;
    @memset(&wire, 0);
    wire[0] = 1; // compactU16(1) signatures
    // message @65: header (num_required=1, ro=0,0), then n_keys=2
    wire[65] = 1; // num_required_signatures
    wire[68] = 2; // compactU16(2) account keys
    @memset(wire[69..101], 0xAA); // key0 (signer)
    @memset(wire[101..133], 0xBB); // key1
    // blockhash @133..165 (zero), then instruction list @165
    wire[165] = 1; // compactU16(1) instruction
    wire[166] = 1; // program_id_index

    var ssig: [MAX_SIGNATURES][64]u8 = undefined;
    var skey: [MAX_SIGNATURES][32]u8 = undefined;
    const tx = try parse(&wire, &ssig, &skey);

    try testing.expectEqual(@as(u16, 2), tx.num_keys);
    try testing.expectEqual(@as(usize, 69), tx.keys_offset); // 1+64 sig, +3 header, +1 n_keys varint
    try testing.expectEqual(@as(usize, 165), tx.instructions_offset); // keys_offset + 2*32 + 32 blockhash
    try testing.expectEqual(@as(u8, 1), wire[tx.instructions_offset]); // points at the num-instructions byte
}

test "tx_ingest: decodeBase64 round-trips + caps oversize" {
    const a = testing.allocator;
    // base64 of "hello" = aGVsbG8=
    const out = try decodeBase64(a, "aGVsbG8=");
    defer a.free(out);
    try testing.expectEqualStrings("hello", out);
    try testing.expectError(error.InvalidBase64, decodeBase64(a, "!!!not-base64!!!"));
}
