//! KAT (Known-Answer Test) for the vote-program AuthorizeChecked carrier fix.
//!
//! Locks the slot-413005757 271KPMd divergence root + its class:
//!   - disc-7 AuthorizeChecked parses (4-byte VoteAuthorize payload, NO pubkey)
//!     instead of silent-dropping through the >=36B AuthorizeData path.
//!   - new authority for AuthorizeChecked comes from ACCOUNT[3], not data.
//!   - target_epoch = leader_schedule_epoch + 1 (canon), NOT current_epoch + 1.
//!   - authorized_voters stays ASCENDING with overwrite-on-exact-key, no evict.
//!   - the v4 leftover tail beyond the rewritten prefix is preserved.
//!   - Tier-2 get_and_update carry-forward + epoch-bounded purge (V3 vs V4).
//!
//! Canon assets (decoded into base64 consts below so the KAT is CI-hermetic —
//! no /mnt/ledger read at runtime):
//!   B756 = canon-756 271KPMd data (AV=[967,968], both -> node BwVDYeT9)
//!   B757 = canon-757 271KPMd data (AV=[967,968,970]); SHA256[0:8]BE u64 =
//!          5051799711597429979.
//!
//! Refs: Agave programs/vote/src/vote_state/{mod.rs,handler.rs},
//! vote_instruction.rs:110; Firedancer fd_vote_program.c:2205-2244,
//! fd_authorized_voters.c, fd_vote_state_v3.c:105-119, fd_vote_state_v4.c:93-106.

const std = @import("std");
const vote_program = @import("vote_program.zig");
const serde = @import("vote_state_serde.zig");
// task #49: PoP crypto-verify is LIVE — VoterWithBLS KATs need a VALID
// (bls_pubkey, proof) pair minted for the test vote account.
const bls = @import("bls_pop");

/// Mint a cryptographically VALID (bls_pubkey, pop) pair for `vote_key`
/// (deterministic keypair; PoP over "ALPENGLOW" || vote_key || bls_pubkey,
/// exactly the SIMD-0387 binding the verifier checks).
pub fn testBlsVector(vote_key: *const [32]u8) struct { pk: [48]u8, pop: [96]u8 } {
    const kp = bls.TestKeypair.fromIkm(&([_]u8{0x42} ** 32));
    var payload: [bls.POP_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(payload[0..9], "ALPENGLOW");
    @memcpy(payload[9..41], vote_key);
    return .{ .pk = kp.pubkey_compressed, .pop = kp.signPop(&payload) };
}

// ── Canon 271KPMd vote-account data, base64 (3762 bytes each) ────────────────
// `pub`: single source of truth for these golden vectors, exercised by the
// proven handleAuthorize port below.
pub const B756 =
    "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";

pub const B757 =
    "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";

// SHA256(canon-757 271KPMd data)[0:8] big-endian u64 — the whole-account gate.
pub const CANON_757_SHA8_BE: u64 = 5051799711597429979;

// BwVDYeT9 = new authority = ACCOUNT[3] (also the node pubkey for this account).
pub const BW_VDYET9: [32]u8 = .{
    0xa2, 0x8a, 0x23, 0x21, 0x7f, 0xb4, 0x0f, 0x62,
    0x82, 0x91, 0x14, 0x97, 0x62, 0x54, 0x9f, 0x37,
    0x8e, 0xbd, 0xde, 0xd2, 0x13, 0x33, 0x2e, 0xdd,
    0x91, 0x2f, 0xdd, 0xd1, 0x69, 0x57, 0xc2, 0xb0,
};

pub fn decodeB64(comptime b64: []const u8, out: *[3762]u8) !void {
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    if (n != 3762) return error.UnexpectedLen;
    try dec.decode(out[0..n], b64);
}

pub fn sha8be(data: []const u8) u64 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.mem.readInt(u64, h[0..8], .big);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 1 — PARSE REGRESSION (Tier 1)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: disc-7 AuthorizeChecked parses 4-byte VoteAuthorize payload (no silent drop)" {
    // 0x07 (disc) + 0x00000000 (VoteAuthorize::Voter) — exactly the 271KPMd ix.
    const ix = [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 0 };
    const parsed = try vote_program.VoteInstruction.deserialize(&ix);
    try std.testing.expect(parsed == .AuthorizeChecked);
    try std.testing.expectEqual(vote_program.AuthorizeType.voter, parsed.AuthorizeChecked.authorize_type);

    // Withdrawer variant (type=1) also parses.
    const ixw = [_]u8{ 0x07, 0, 0, 0, 1, 0, 0, 0 };
    const pw = try vote_program.VoteInstruction.deserialize(&ixw);
    try std.testing.expectEqual(vote_program.AuthorizeType.withdrawer, pw.AuthorizeChecked.authorize_type);

    // Pre-fix: disc 7 routed to AuthorizeData.deserialize (>=36B) and a 4-byte
    // payload returned error.InvalidData. Assert the standalone parser rejects
    // a <4B payload but NOT this 4B one.
    try std.testing.expectError(error.InvalidData, vote_program.AuthorizeCheckedData.deserialize(&[_]u8{ 0, 0 }));
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 2 — AUTHORIZE-CHECKED TRANSFORM ON 756 (Tier 1, structural, NO whole-hash)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: AuthorizeChecked(Voter) on canon-756 271KPMd inserts AV[970]=account[3] ascending" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B756, &buf);

    // Pre-state sanity: V4 (version==3), AV=[(967,BW),(968,BW)].
    const pre = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 3), pre.version);
    try std.testing.expectEqual(@as(u32, 2), pre.av_count);
    try std.testing.expectEqual(@as(u64, 967), pre.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 968), pre.authorized_voters[1].epoch);

    // account[3] = BW. accounts = [vote, clock, BW(signer), BW(signer)].
    const vote_key = [_]u8{0xAA} ** 32; // arbitrary; not signer-checked in the AV insert
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2, 3 };
    const num_required_sigs: u8 = 4; // BW signs (idx 2 & 3 within sig range)

    // current_epoch=968, leader_schedule_epoch=969 -> target_epoch 970.
    const ok = vote_program.handleAuthorize(
        .voter,
        BW_VDYET9, // new_authority resolved from account[3]
        &account_keys,
        &account_indices,
        num_required_sigs,
        &buf,
        968, // current_epoch
        969, // leader_schedule_epoch
        true, // is_checked
        null, // bls_pubkey (plain Voter)
        null, // bls_proof_of_possession (plain Voter)
    );
    try std.testing.expect(ok);

    const post = serde.deserializeVoteState(&buf).?;
    // AV becomes ascending [(967,BW),(968,BW),(970,BW)]. (get_and_update at
    // ce=968 is exact-hit no-op; V4 purge<967 removes nothing.)
    try std.testing.expectEqual(@as(u32, 3), post.av_count);
    try std.testing.expectEqual(@as(u64, 967), post.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 968), post.authorized_voters[1].epoch);
    try std.testing.expectEqual(@as(u64, 970), post.authorized_voters[2].epoch);
    try std.testing.expectEqualSlices(u8, &BW_VDYET9, &post.authorized_voters[2].pubkey);

    // Pre-AV region (version + node + withdrawer = bytes [0..68)) byte-identical
    // to the 756 input (authorize does NOT touch identity/withdrawer).
    var orig756: [3762]u8 = undefined;
    try decodeB64(B756, &orig756);
    try std.testing.expectEqualSlices(u8, orig756[0..68], buf[0..68]);

    // Structural proof that authorize mutated ONLY the AV map — the tower
    // (lockouts/root), epoch_credits, and timestamp are UNCHANGED vs 756.
    // (spec kat_plan item 2: "lockout/credits region byte-IDENTICAL to 756".)
    try std.testing.expectEqual(pre.lockout_count, post.lockout_count);
    for (0..pre.lockout_count) |i| {
        try std.testing.expectEqual(pre.lockouts[i].slot, post.lockouts[i].slot);
        try std.testing.expectEqual(pre.lockouts[i].confirmation_count, post.lockouts[i].confirmation_count);
        try std.testing.expectEqual(pre.latencies[i], post.latencies[i]);
    }
    try std.testing.expectEqual(pre.root_slot, post.root_slot);
    try std.testing.expectEqual(pre.ec_count, post.ec_count);
    for (0..pre.ec_count) |i| {
        try std.testing.expectEqual(pre.epoch_credits[i].epoch, post.epoch_credits[i].epoch);
        try std.testing.expectEqual(pre.epoch_credits[i].credits, post.epoch_credits[i].credits);
        try std.testing.expectEqual(pre.epoch_credits[i].prev_credits, post.epoch_credits[i].prev_credits);
    }
    try std.testing.expectEqual(pre.last_timestamp.slot, post.last_timestamp.slot);
    try std.testing.expectEqual(pre.last_timestamp.timestamp, post.last_timestamp.timestamp);
    // AV[0..2] (the carried-forward 967/968 entries) also unchanged.
    try std.testing.expectEqual(pre.authorized_voters[0].epoch, post.authorized_voters[0].epoch);
    try std.testing.expectEqualSlices(u8, &pre.authorized_voters[0].pubkey, &post.authorized_voters[0].pubkey);
    try std.testing.expectEqual(pre.authorized_voters[1].epoch, post.authorized_voters[1].epoch);
    try std.testing.expectEqualSlices(u8, &pre.authorized_voters[1].pubkey, &post.authorized_voters[1].pubkey);

    // REAL-bytes lock on handleAuthorize's V4 STALE-TAIL preservation (the
    // `vs.version != 3` no-zero path). After the authorize, everything past the
    // serialized state must be the 756 residue VERBATIM — NOT zeroed. An earlier
    // VoterWithBLS attempt zeroed this tail and diverged @414056489; this assert
    // would have caught it. (Can't use a whole-account hash vs 757: 757 also
    // advanced the lockout tower — first byte-diff is at offset 154, the votes
    // region — so 756→757 is authorize+vote, not a pure authorize.)
    var reout: [3762]u8 = undefined;
    @memcpy(&reout, &buf);
    const wlen = serde.serializeVoteState(&post, &reout).?;
    try std.testing.expect(wlen < 3762);
    try std.testing.expectEqualSlices(u8, orig756[wlen..], buf[wlen..]); // tail preserved
    var residue_nonzero = false;
    for (orig756[wlen..]) |b| {
        if (b != 0) {
            residue_nonzero = true;
            break;
        }
    }
    try std.testing.expect(residue_nonzero); // the residue is real (test is meaningful)
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 3 — ROUND-TRIP IDEMPOTENCE (the whole-account hash gate)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: deser(canon-757 271KPMd) -> serialize round-trips to SHA8 5051799711597429979" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B757, &buf);
    // Sanity: input itself hashes to the canon value.
    try std.testing.expectEqual(CANON_757_SHA8_BE, sha8be(&buf));

    const vs = serde.deserializeVoteState(&buf).?;
    var out: [3762]u8 = undefined;
    @memcpy(&out, &buf); // start from the same bytes so the v4 tail is present
    const written = serde.serializeVoteState(&vs, &out).?;
    // V4 serializes a prefix SHORTER than the fixed 3762B account; the leftover
    // tail [written..3762) is the v3->v4 migration residue, preserved verbatim
    // (version==3 → no memset). Whole-account SHA8 over the full 3762B buffer
    // must match canon-757 exactly — locks the V4 serde byte-layout + tail.
    try std.testing.expect(written > 0 and written <= 3762);
    try std.testing.expectEqual(CANON_757_SHA8_BE, sha8be(&out));
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 4 — CARRY-FORWARD get_and_update VECTOR (Tier 2 — 757 does NOT exercise)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: getAndUpdateAuthorizedVoter V4 carry-forward + purge (ascending into middle)" {
    const N = [_]u8{0x11} ** 32;
    const B = [_]u8{0x22} ** 32;
    var vs = serde.VoteState.init();
    vs.version = 3; // V4
    vs.av_count = 3;
    vs.authorized_voters[0] = .{ .epoch = 967, .pubkey = N };
    vs.authorized_voters[1] = .{ .epoch = 968, .pubkey = N };
    vs.authorized_voters[2] = .{ .epoch = 970, .pubkey = B };

    // ce=969: carry-forward inserts {969,N} (predecessor 968's pubkey) ascending
    // between 968 and 970; V4 purge(<sat_sub(969,1)=968) drops 967.
    try std.testing.expect(serde.getAndUpdateAuthorizedVoter(&vs, 969));
    try std.testing.expectEqual(@as(u32, 3), vs.av_count);
    try std.testing.expectEqual(@as(u64, 968), vs.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 969), vs.authorized_voters[1].epoch);
    try std.testing.expectEqual(@as(u64, 970), vs.authorized_voters[2].epoch);
    try std.testing.expectEqualSlices(u8, &N, &vs.authorized_voters[1].pubkey); // carried from 968
    try std.testing.expectEqualSlices(u8, &B, &vs.authorized_voters[2].pubkey);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 5 — EXACT-HIT NO-OP (Tier 2) — why slot 757 is a byte no-op
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: getAndUpdateAuthorizedVoter exact-hit on ce is a no-op (757 case)" {
    const N = [_]u8{0x33} ** 32;
    var vs = serde.VoteState.init();
    vs.version = 3; // V4
    vs.av_count = 2;
    vs.authorized_voters[0] = .{ .epoch = 967, .pubkey = N };
    vs.authorized_voters[1] = .{ .epoch = 968, .pubkey = N };

    // ce=968: exact hit -> no carry-forward insert; V4 purge(<967) removes none.
    try std.testing.expect(serde.getAndUpdateAuthorizedVoter(&vs, 968));
    try std.testing.expectEqual(@as(u32, 2), vs.av_count);
    try std.testing.expectEqual(@as(u64, 967), vs.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 968), vs.authorized_voters[1].epoch);
}

// V3 purge bound differs from V4 (bound=ce, not ce-1).
test "KAT: getAndUpdateAuthorizedVoter V3 purge bound = current_epoch" {
    const N = [_]u8{0x44} ** 32;
    var vs = serde.VoteState.init();
    vs.version = 2; // V3-family (not the V4 wire disc 3)
    vs.av_count = 2;
    vs.authorized_voters[0] = .{ .epoch = 967, .pubkey = N };
    vs.authorized_voters[1] = .{ .epoch = 968, .pubkey = N };

    // ce=968: exact hit; V3 purge(<968) drops 967 (V4 would keep it at <967).
    try std.testing.expect(serde.getAndUpdateAuthorizedVoter(&vs, 968));
    try std.testing.expectEqual(@as(u32, 1), vs.av_count);
    try std.testing.expectEqual(@as(u64, 968), vs.authorized_voters[0].epoch);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 6 — Authorize (disc 1) data-pubkey path still works
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: Authorize(disc 1) uses data pubkey as new authority (ascending insert)" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B756, &buf);

    // New authority comes from data for disc 1. Use a fresh distinguishable key.
    const NEW = [_]u8{0x5A} ** 32;
    // Current voter (BW) must sign for the authorize-voter path.
    const vote_key = [_]u8{0xAA} ** 32;
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2 };
    const num_required_sigs: u8 = 3;

    const ok = vote_program.handleAuthorize(
        .voter,
        NEW, // disc 1: new authority is the data pubkey
        &account_keys,
        &account_indices,
        num_required_sigs,
        &buf,
        968, // current_epoch
        969, // leader_schedule_epoch -> target 970
        false, // is_checked = false (no account[3] signer requirement)
        null, // bls_pubkey (plain Voter)
        null, // bls_proof_of_possession (plain Voter)
    );
    try std.testing.expect(ok);

    const post = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 3), post.av_count);
    try std.testing.expectEqual(@as(u64, 970), post.authorized_voters[2].epoch);
    try std.testing.expectEqualSlices(u8, &NEW, &post.authorized_voters[2].pubkey);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 7 — too_soon_to_reauthorize rejects on duplicate target_epoch
// ─────────────────────────────────────────────────────────────────────────────
test "KAT: Authorize rejects when target_epoch already present (TooSoonToReauthorize)" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B756, &buf);
    // 756 AV=[967,968]. With lse=967 -> target 968 already present -> reject.
    const vote_key = [_]u8{0xAA} ** 32;
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2, 3 };
    const ok = vote_program.handleAuthorize(
        .voter,
        BW_VDYET9,
        &account_keys,
        &account_indices,
        4,
        &buf,
        967, // current_epoch (exact-hit on 967, no-op get_and_update)
        967, // lse -> target 968 (already in AV)
        true,
        null, // bls_pubkey (plain Voter)
        null, // bls_proof_of_possession (plain Voter)
    );
    try std.testing.expect(!ok); // rejected, no state change
    // Buffer unchanged (handleAuthorize returns before serialize on reject).
    var orig: [3762]u8 = undefined;
    try decodeB64(B756, &orig);
    try std.testing.expectEqualSlices(u8, &orig, &buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT 7 — VoterWithBLS (SIMD-0387 / SIMD-0185) — the @414056489 carrier
// ─────────────────────────────────────────────────────────────────────────────
// Locks the VoterWithBLS authorize that Vexor used to silent-drop (disc-2 failed
// intToEnum on the {voter,withdrawer} enum). PROVEN @414056489: registering a BLS
// pubkey on vote acct 8iiZpnZo… → bank_hash/lthash diverged until this path landed.

test "KAT: AuthorizeChecked(VoterWithBLS) parses disc-2 + extracts 48B bls_pubkey" {
    // [outer disc 7][VoteAuthorize::VoterWithBLS=2][bls_pubkey:48][pop:96] = 152B.
    var ix: [152]u8 = undefined;
    @memset(&ix, 0);
    ix[0] = 7; // VoteInstruction::AuthorizeChecked
    ix[4] = 2; // VoteAuthorize::VoterWithBLS
    const expected_bls = [_]u8{0xBE} ** 48;
    @memcpy(ix[8..56], &expected_bls);
    @memset(ix[56..152], 0x90); // bls_proof_of_possession (96B; parse-level only here)

    const parsed = try vote_program.VoteInstruction.deserialize(&ix);
    try std.testing.expect(parsed == .AuthorizeChecked);
    try std.testing.expectEqual(vote_program.AuthorizeType.voter_with_bls, parsed.AuthorizeChecked.authorize_type);
    try std.testing.expect(parsed.AuthorizeChecked.bls_pubkey != null);
    try std.testing.expectEqualSlices(u8, &expected_bls, &parsed.AuthorizeChecked.bls_pubkey.?);
    // task #49: the 96B proof-of-possession is now extracted too (no longer dropped).
    try std.testing.expect(parsed.AuthorizeChecked.bls_proof_of_possession != null);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x90} ** 96), &parsed.AuthorizeChecked.bls_proof_of_possession.?);

    // Truncated args (payload < 4+48+96 = 148B) → reject (matches Agave bincode).
    try std.testing.expectError(error.InvalidData, vote_program.AuthorizeCheckedData.deserialize(ix[4..151]));
}

test "KAT: handleAuthorize(VoterWithBLS) on 756 sets bls_pubkey + inserts AV[970]" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B756, &buf);
    const pre = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 3), pre.version); // V4
    try std.testing.expect(!pre.has_bls_pubkey_compressed); // 756 has no BLS yet

    const vote_key = [_]u8{0xAA} ** 32;
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2, 3 };
    // task #49: the PoP is now cryptographically VERIFIED — mint a valid
    // (pubkey, pop) pair bound to this test vote account.
    const vec = testBlsVector(&vote_key);
    const expected_bls = vec.pk;

    const ok = vote_program.handleAuthorize(
        .voter_with_bls,
        BW_VDYET9, // new_authority = account[3]
        &account_keys,
        &account_indices,
        4, // num_required_sigs (BW signs)
        &buf,
        968, // current_epoch
        969, // leader_schedule_epoch -> target 970
        true, // is_checked
        expected_bls, // SIMD-0387 bls_pubkey
        vec.pop, // SIMD-0387 proof-of-possession (VALID — verified by blst)
    );
    try std.testing.expect(ok);

    const post = serde.deserializeVoteState(&buf).?;
    // Same voter-authorize result as plain Voter (AV ascending [967,968,970]=BW)...
    try std.testing.expectEqual(@as(u32, 3), post.av_count);
    try std.testing.expectEqual(@as(u64, 970), post.authorized_voters[2].epoch);
    try std.testing.expectEqualSlices(u8, &BW_VDYET9, &post.authorized_voters[2].pubkey);
    // ...PLUS the BLS pubkey is now registered into the V4 frame.
    try std.testing.expect(post.has_bls_pubkey_compressed);
    try std.testing.expectEqualSlices(u8, &expected_bls, &post.bls_pubkey_compressed);

    // Round-trip: re-serializing the parsed post-state reproduces the written bytes
    // (locks the bls offset-145 layout end-to-end).
    var out: [3762]u8 = undefined;
    @memcpy(&out, &buf);
    const w = serde.serializeVoteState(&post, &out).?;
    try std.testing.expectEqualSlices(u8, buf[0..w], out[0..w]);
}

// task #49: an INVALID proof-of-possession must REJECT the VoterWithBLS
// authorize with NO state change (Agave mod.rs:740-745 verify_bls_proof_of_
// possession → InstructionError::InvalidArgument BEFORE set_new_authorized_voter;
// this bool-handler signals failure via `false`). Covers bit-flipped pop,
// valid-PoP-wrong-account (replay), and garbage pubkey.
test "KAT: handleAuthorize(VoterWithBLS) REJECTS invalid proof-of-possession, no state change" {
    var buf: [3762]u8 = undefined;
    try decodeB64(B756, &buf);
    var orig: [3762]u8 = undefined;
    @memcpy(&orig, &buf);

    const vote_key = [_]u8{0xAA} ** 32;
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2, 3 };
    const vec = testBlsVector(&vote_key);

    // (a) bit-flipped PoP.
    var bad_pop = vec.pop;
    bad_pop[40] ^= 0x01;
    try std.testing.expect(!vote_program.handleAuthorize(
        .voter_with_bls,
        BW_VDYET9,
        &account_keys,
        &account_indices,
        4,
        &buf,
        968,
        969,
        true,
        vec.pk,
        bad_pop,
    ));
    try std.testing.expectEqualSlices(u8, &orig, &buf); // untouched

    // (b) valid PoP bound to a DIFFERENT vote account (replay attack).
    const other_key = [_]u8{0xAB} ** 32;
    const other_vec = testBlsVector(&other_key);
    try std.testing.expect(!vote_program.handleAuthorize(
        .voter_with_bls,
        BW_VDYET9,
        &account_keys,
        &account_indices,
        4,
        &buf,
        968,
        969,
        true,
        other_vec.pk,
        other_vec.pop, // signed over 0xAB… but account[0] is 0xAA…
    ));
    try std.testing.expectEqualSlices(u8, &orig, &buf);

    // (c) the old golden 0xBE**48 garbage pubkey (not even a valid G1 point).
    try std.testing.expect(!vote_program.handleAuthorize(
        .voter_with_bls,
        BW_VDYET9,
        &account_keys,
        &account_indices,
        4,
        &buf,
        968,
        969,
        true,
        [_]u8{0xBE} ** 48,
        [_]u8{0x90} ** 96,
    ));
    try std.testing.expectEqualSlices(u8, &orig, &buf);
}

// A plain Voter authorize is REJECTED once the account already has a BLS pubkey
// (Agave mod.rs:704 guard; feature active). VoterWithBLS is exempt (tested above).
test "KAT: plain Voter authorize rejected when account already has BLS pubkey" {
    var vs = serde.VoteState.init();
    vs.version = 3; // V4
    vs.has_bls_pubkey_compressed = true;
    @memset(&vs.bls_pubkey_compressed, 0xBE);
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 968, .pubkey = BW_VDYET9 };
    vs.node_pubkey = BW_VDYET9;
    vs.authorized_withdrawer = BW_VDYET9;
    var buf: [3762]u8 = undefined;
    @memset(&buf, 0);
    _ = serde.serializeVoteState(&vs, &buf).?;

    const vote_key = [_]u8{0xAA} ** 32;
    const clock_key = [_]u8{0xCC} ** 32;
    const account_keys = [_][32]u8{ vote_key, clock_key, BW_VDYET9, BW_VDYET9 };
    const account_indices = [_]u8{ 0, 1, 2, 3 };
    const ok = vote_program.handleAuthorize(
        .voter, // plain Voter — must be rejected because has_bls is set
        BW_VDYET9,
        &account_keys,
        &account_indices,
        4,
        &buf,
        968,
        969,
        true,
        null,
        null,
    );
    try std.testing.expect(!ok); // rejected (no state change)
}
