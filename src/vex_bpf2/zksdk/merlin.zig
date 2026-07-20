//! Merlin transcripts: a Strobe-128 (over Keccak-f[1600]) sponge construction that
//! turns an interactive sigma/range-proof protocol into a non-interactive one via
//! Fiat-Shamir. Every value a proof commits to — points, scalars, ciphertexts,
//! domain separators — is absorbed into the sponge in a fixed order; every
//! challenge a verifier needs is squeezed back out. Because the sponge mixes ALL
//! prior input into its state before producing any output, a challenge cannot be
//! chosen (or predicted) without having already committed to everything absorbed
//! before it — that binding is the entire security argument for the proofs built
//! on top of this file.
//!
//! CONSENSUS-CRITICAL, and the strictest module in the zksdk port: sigma_proofs/
//! and range_proof/ derive every Fiat-Shamir challenge from a `Transcript`, so a
//! single wrong byte in any state transition here silently changes every
//! downstream challenge and flips proof verdicts (which feed bank_hash). Unlike
//! pedersen/elgamal group math, Strobe's framing (the exact bytes of the
//! begin-operation/permute-boundary logic below) has no "any correct
//! implementation converges" property — it must be bit-for-bit what Agave's
//! `merlin` crate does. Fully deterministic: no OS/time entropy anywhere in this
//! file, so every operation is byte-comparable old-vs-new (see
//! kat_module2_parity.zig).
//!
//! https://merlin.cool/use/protocol.html
//! https://strobe.sourceforge.io/papers/strobe-20170130.pdf
//! [agave] https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/zk-sdk/src/transcript.rs
//! [merlin crate] https://docs.rs/merlin/latest/src/merlin/strobe.rs.html

const std = @import("std");
const builtin = @import("builtin");
const elgamal = @import("elgamal.zig");
const pedersen = @import("pedersen.zig");

/// Already byte-equivalent to the vendored Strobe/Keccak internals this module
/// used to carry (proven in kat_module2_parity.zig): the sponge permutation
/// itself is generic algebra with no protocol-specific framing, so there is
/// nothing "vendored" left to restructure here — we just drive std's permutation
/// with Strobe's own state layout and padding rules (below).
const Keccak1600 = std.crypto.core.keccak.KeccakF(1600);
const Ed25519 = std.crypto.ecc.Edwards25519;
const Scalar = Ed25519.scalar.Scalar;
const Ristretto255 = std.crypto.ecc.Ristretto255;

/// Strobe-128 duplex sponge: the primitive Merlin layers its transcript framing
/// on top of. "128" is the targeted security level, which fixes the sponge's
/// rate `R` (bytes absorbed/squeezed per permutation) below the 200-byte Keccak
/// state width — the remaining capacity bytes are what make the construction
/// hard to invert.
pub const Strobe128 = struct {
    state: Keccak1600,
    /// Byte offset within the rate where the next absorb/squeeze/overwrite lands.
    position: u8,
    /// Byte offset where the *current* operation began — recorded so
    /// `permuteState` can XOR it back in as the operation's framing byte
    /// (Strobe mixes "where did this op start" into the state, not just "what
    /// data did it carry").
    begin: u8,
    /// Flags of the operation currently in progress; re-checked on every
    /// `more=true` continuation call to catch a caller trying to split a single
    /// logical operation across incompatible flag sets.
    flags: Flags,

    /// Per-operation flags, absorbed as a single framing byte at `beginOp`. Field
    /// order is part of the wire format (packed struct = bit position = meaning):
    /// bit0=I (inbound), bit1=A (application data), bit2=C (cipher/PRF output),
    /// bit3=T (transport direction — unused here, asserted false), bit4=M (meta,
    /// i.e. framing-about-framing such as labels/lengths), bit5=K (keying).
    pub const Flags = packed struct(u8) {
        I: bool = false,
        A: bool = false,
        C: bool = false,
        T: bool = false,
        M: bool = false,
        K: bool = false,
        _padding: u2 = 0,
    };

    /// Sponge rate in bytes for the 128-bit security level: `200 - 2*(128/8) = 166`.
    /// Hardcoded because this transcript never operates at any other security level.
    pub const R = 166;

    /// Domain-separates a fresh transcript by its protocol label. Mirrors the
    /// `merlin` crate's `Strobe128::new`: seed the Keccak state with Strobe's
    /// fixed initialization string, permute once, then absorb the label as the
    /// first meta-AD operation (see `metaAd`).
    pub fn init(label: []const u8) Strobe128 {
        const initial_state = state: {
            var state: [200]u8 = @splat(0);
            // Strobe's fixed init vector: protocol/security-level/version bytes
            // followed by the ASCII tag "STROBEv1.0.2". Not configurable — this
            // exact byte sequence is what makes two independent Strobe
            // implementations agree on the same starting sponge state.
            state[0..6].* = .{ 1, R + 2, 1, 0, 1, 96 };
            state[6..18].* = "STROBEv1.0.2".*;

            var k = Keccak1600.init(state);
            k.permute();
            break :state k;
        };

        var strobe: Strobe128 = .{
            .state = initial_state,
            .position = 0,
            .begin = 0,
            .flags = .{},
        };
        strobe.metaAd(label, false);
        return strobe;
    }

    /// Direct view over the sponge's 200-byte state, shared by absorb/squeeze/
    /// overwrite/permuteState so they don't each re-derive the same pointer cast.
    fn stateBytes(self: *Strobe128) *[200]u8 {
        return @ptrCast(&self.state.st);
    }

    /// Frames the start of a Strobe operation (AD, meta-AD, PRF, or key). Every
    /// operation begins by absorbing two bytes: `begin` (the rate-position the
    /// *previous* operation ended at) and the new operation's flags byte. This is
    /// what lets a verifier reconstructing the transcript detect if operations
    /// were reordered or their boundaries shifted, even though the payload bytes
    /// look the same.
    pub fn beginOp(self: *Strobe128, flags: Flags, more: bool) void {
        if (more) {
            // A continuation must carry the exact same flags as the operation
            // it's continuing — Strobe has no concept of "half AD, half PRF".
            std.debug.assert(self.flags == flags);
            return;
        }

        // T (transport direction) distinguishes inbound-from-peer vs
        // outbound-to-peer bytes in interactive Strobe protocols. Merlin's
        // transcripts are non-interactive (prover and verifier both derive the
        // same bytes locally), so no call site ever sets it.
        std.debug.assert(!flags.T);

        const old_begin = self.begin;
        self.begin = self.position + 1;
        self.flags = flags;

        self.absorb(&.{ old_begin, @bitCast(flags) });

        // C (cipher output) or K (keying) operations must start from a clean
        // rate window, so force a permutation boundary unless we're already at
        // one (position == 0 means the previous operation ended exactly on the
        // rate boundary and there's nothing pending to flush).
        const force_permute = flags.C or flags.K;
        if (force_permute and self.position != 0) {
            self.permuteState();
        }
    }

    /// Closes out the current rate window and runs the Keccak-f[1600]
    /// permutation. The two XORs before permuting are Strobe's padding: `begin`
    /// re-affirms where this operation started (defense against boundary
    /// confusion across permutations) and `0x04` is the frame-end marker;
    /// `R + 1 |= 0x80` sets Keccak's domain-separation/multi-rate padding bit at
    /// the last byte of the rate. Position and begin both reset to 0 — the next
    /// operation starts fresh at the top of the new state.
    fn permuteState(self: *Strobe128) void {
        const state = self.stateBytes();
        state[self.position] ^= self.begin;
        state[self.position + 1] ^= 0x04;
        state[R + 1] ^= 0x80;

        self.state.permute();
        self.position = 0;
        self.begin = 0;
    }

    /// XORs `data` into the sponge state byte-by-byte, permuting every time the
    /// rate window fills. This is the sponge's absorb primitive: input can never
    /// be read back out, only its influence on the (irreversible) permutation
    /// output remains.
    fn absorb(self: *Strobe128, data: []const u8) void {
        const state = self.stateBytes();
        for (data) |byte| {
            state[self.position] ^= byte;
            self.position += 1;
            if (self.position == R) self.permuteState();
        }
    }

    /// Reads `destination.len` pseudorandom bytes out of the sponge state,
    /// zeroing each byte immediately after it's read. The zeroing matters: it
    /// keeps the emitted output from being absorbed again by a later operation
    /// that reuses this rate window without an intervening permutation, and it
    /// destroys any trace of the un-squeezed value from the live state.
    fn squeeze(self: *Strobe128, destination: []u8) void {
        const state = self.stateBytes();
        for (destination) |*byte| {
            byte.* = state[self.position];
            state[self.position] = 0;
            self.position += 1;
            if (self.position == R) self.permuteState();
        }
    }

    /// Writes `destination` directly into the sponge state (no XOR) — used only
    /// for `key`, which re-keys the sponge rather than absorbing input alongside
    /// whatever was already there.
    fn overwrite(self: *Strobe128, destination: []const u8) void {
        const state = self.stateBytes();
        for (destination) |byte| {
            state[self.position] = byte;
            self.position += 1;
            if (self.position == R) self.permuteState();
        }
    }

    /// Absorbs "meta" associated data: framing *about* framing (operation
    /// labels, encoded lengths) rather than protocol payload. Kept as a
    /// distinct flag combination (M|A) so meta and payload bytes can never be
    /// confused even if their raw contents collide.
    pub fn metaAd(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .M = true, .A = true }, more);
        self.absorb(data);
    }

    /// Absorbs associated data: the actual protocol payload (point/scalar/etc.
    /// encodings) being committed into the transcript.
    pub fn ad(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .A = true }, more);
        self.absorb(data);
    }

    /// Squeezes a pseudorandom function output — this is how Fiat-Shamir
    /// challenges are drawn: deterministic given everything absorbed so far,
    /// unpredictable without it.
    pub fn prf(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .I = true, .A = true, .C = true }, more);
        self.squeeze(destination);
    }

    /// Re-keys the sponge with `destination`'s current contents (overwritten in
    /// place). Not used by the zk-elgamal-proof transcripts themselves, but part
    /// of the Strobe primitive's public surface.
    pub fn key(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .A = true, .C = true }, more);
        self.overwrite(destination);
    }

    test "conformance" {
        var s1 = Strobe128.init("Conformance Test Protocol");
        const msg: [1024]u8 = @splat(99);

        s1.metaAd("ms", false);
        s1.metaAd("g", true);
        s1.ad(&msg, false);

        var prf1: [32]u8 = @splat(0);
        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0xb4, 0x8e, 0x64, 0x5c, 0xa1, 0x7c, 0x66, 0x7f,
                0xd5, 0x20, 0x6b, 0xa5, 0x7a, 0x6a, 0x22, 0x8d,
                0x72, 0xd8, 0xe1, 0x90, 0x38, 0x14, 0xd3, 0xf1,
                0x7f, 0x62, 0x29, 0x96, 0xd7, 0xcf, 0xef, 0xb0,
            },
            &prf1,
        );

        s1.metaAd("key", false);
        s1.key(&prf1, false);

        @memset(&prf1, 0);

        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0x7,  0xe4, 0x5c, 0xce, 0x80, 0x78, 0xce, 0xe2,
                0x59, 0xe3, 0xe3, 0x75, 0xbb, 0x85, 0xd7, 0x56,
                0x10, 0xe2, 0xd1, 0xe1, 0x20, 0x1c, 0x5f, 0x64,
                0x50, 0x45, 0xa1, 0x94, 0xed, 0xd4, 0x9f, 0xf8,
            },
            &prf1,
        );
    }
};

/// A Merlin transcript layered over Strobe128: the zk-elgamal-proof program's
/// Fiat-Shamir accumulator. Every proof appends its public inputs in a fixed
/// order (`append`/`appendDomSep`/`appendRangeProof`) and then draws challenges
/// (`challengeScalar`) that the verifier can independently reproduce byte-for-
/// byte given the same public inputs — that reproduction, not any secret, is
/// what "verifying a proof" reduces to.
pub const Transcript = struct {
    strobe: Strobe128,

    /// One domain separator per proof/instruction kind. Appended via
    /// `appendDomSep`/`Transcript.init` so that a transcript built for one proof
    /// type can never be replayed as valid input to a different one — the very
    /// first bytes absorbed pin the proof kind.
    pub const DomainSeperator = enum {
        @"zero-ciphertext-instruction",
        @"zero-ciphertext-proof",
        @"pubkey-validity-instruction",
        @"pubkey-proof",
        @"percentage-with-cap-proof",
        @"percentage-with-cap-instruction",
        @"ciphertext-commitment-equality-proof",
        @"ciphertext-commitment-equality-instruction",
        @"ciphertext-ciphertext-equality-proof",
        @"ciphertext-ciphertext-equality-instruction",

        @"inner-product",
        @"range-proof",
        @"batched-range-proof-instruction",

        @"validity-proof",
        @"batched-validity-proof",

        @"grouped-ciphertext-validity-2-handles-instruction",
        @"batched-grouped-ciphertext-validity-2-handles-instruction",

        @"grouped-ciphertext-validity-3-handles-instruction",
        @"batched-grouped-ciphertext-validity-3-handles-instruction",
    };

    /// Every value a sigma/range proof can bind into the transcript. Each variant
    /// has exactly one wire encoding (below, in `appendMessage`) — the union
    /// shape lets `append`'s `Session` contract check, at compile time, that
    /// callers append the type the protocol contract expects at each position.
    const Message = union(enum) {
        bytes: []const u8,

        point: Ristretto255,
        pubkey: elgamal.Pubkey,
        scalar: Scalar,
        ciphertext: elgamal.Ciphertext,
        commitment: pedersen.Commitment,
        u64: u64,
        domsep: DomainSeperator,

        grouped_2: elgamal.GroupedElGamalCiphertext(2),
        grouped_3: elgamal.GroupedElGamalCiphertext(3),
    };

    /// Top-level domain string absorbed into every transcript before any
    /// proof-specific domain separator — pins the entire transcript to this
    /// program, independent of what else on-chain might use Merlin/Strobe.
    ///
    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/lib.rs#L36
    const TRANSCRIPT_DOMAIN = "solana-zk-elgamal-proof-program-v1";

    /// Starts a fresh transcript for `seperator`'s proof kind: seeds Strobe with
    /// the fixed "Merlin v1.0" label (mirroring the `merlin` crate's
    /// `Transcript::new`), then absorbs the two-level domain separation
    /// (program-wide, then proof-specific).
    pub fn init(comptime seperator: DomainSeperator) Transcript {
        var transcript: Transcript = .{ .strobe = Strobe128.init("Merlin v1.0") };
        transcript.appendBytes("dom-sep", TRANSCRIPT_DOMAIN);
        transcript.appendBytes("dom-sep", @tagName(seperator));
        return transcript;
    }

    /// Test-only variant of `init` that takes an arbitrary label instead of a
    /// `DomainSeperator` — lets tests reproduce the reference `merlin` crate's
    /// example transcripts (which use free-form protocol labels) without adding
    /// a test-only enum member to the production `DomainSeperator` type.
    pub fn initTest(label: []const u8) Transcript {
        comptime if (!builtin.is_test) @compileError("should only be used during tests");
        var transcript: Transcript = .{ .strobe = Strobe128.init("Merlin v1.0") };
        transcript.appendBytes("dom-sep", TRANSCRIPT_DOMAIN);
        transcript.appendBytes("dom-sep", label);
        return transcript;
    }

    /// Appends one length-prefixed byte string under `label`: this is Merlin's
    /// `append_message` — meta-AD the label, meta-AD the little-endian u32
    /// length (as a continuation of the same logical meta-AD operation, hence
    /// `more=true`), then AD the payload itself. Prefixing the length (rather
    /// than relying on a delimiter) is what stops two different (label, bytes)
    /// pairs from ever absorbing to the same byte stream.
    fn appendBytes(self: *Transcript, label: []const u8, bytes: []const u8) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(bytes.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&data_len, true);
        self.strobe.ad(bytes, false);
    }

    /// Encodes `message` to its canonical wire bytes and forwards to
    /// `appendBytes`. Every case here must match Agave's `Transcript::append_*`
    /// encoding exactly — a mismatched byte order or field layout here is
    /// indistinguishable, from the sponge's perspective, from a different input
    /// entirely. `buffer` is stack-local and sized for the widest variant
    /// (ciphertext: two 32-byte compressed points).
    fn appendMessage(self: *Transcript, label: []const u8, message: Message) void {
        var buffer: [64]u8 = @splat(0);
        const bytes: []const u8 = switch (message) {
            .bytes => |b| b,
            .point => |*point| &point.toBytes(),
            .pubkey => |*pubkey| &pubkey.toBytes(),
            .scalar => |*scalar| &scalar.toBytes(),
            .domsep => |t| @tagName(t),
            .ciphertext => |*ct| b: {
                @memcpy(buffer[0..32], &ct.commitment.point.toBytes());
                @memcpy(buffer[32..64], &ct.handle.point.toBytes());
                break :b &buffer;
            },
            .commitment => |*c| &c.toBytes(),
            .u64 => |x| b: {
                std.mem.writeInt(u64, buffer[0..8], x, .little);
                break :b buffer[0..8];
            },
            inline .grouped_2, .grouped_3 => |*g| &g.toBytes(),
        };
        self.appendBytes(label, bytes);
    }

    /// Appends `data` at the caller's current position in `session`'s compile-
    /// time protocol contract. `session.nextInput` enforces, at compile time,
    /// that the (type, label) pair matches what the contract expects next — a
    /// proof can't accidentally append its values out of order or under the
    /// wrong label, both of which would silently desync prover and verifier
    /// transcripts. When `t` requires identity validation (a point that must
    /// not be the group identity — accepting it would let a prover construct a
    /// degenerate, universally-"valid" proof), that check runs before the value
    /// ever reaches the sponge; `session.cancel()` on the errdefer path records
    /// that the contract was intentionally abandoned so `Session.finish` won't
    /// flag it as incomplete.
    pub inline fn append(
        self: *Transcript,
        comptime session: *Session,
        comptime t: Input.Type,
        comptime label: []const u8,
        data: @FieldType(Message, @tagName(t.base())),
    ) if (t.validates()) error{IdentityElement}!void else void {
        errdefer session.cancel();

        const input = comptime session.nextInput(t, label);
        if (comptime t.validates()) try data.rejectIdentity();
        // Domain separators must only ever be appended through `appendDomSep`,
        // which is the sole caller passing `t == .domsep` — assert both the
        // label and the expected separator to catch any future call site that
        // tries to append one directly.
        switch (t) {
            .domsep => comptime {
                std.debug.assert(input.seperator.? == data);
                std.debug.assert(std.mem.eql(u8, label, "dom-sep"));
            },
            else => {},
        }

        self.appendMessage(input.label, @unionInit(
            Message,
            @tagName(t.base()),
            data,
        ));
    }

    /// Same as `append` but skips the identity-element rejection. Proof `init`
    /// functions use this specifically to probe "what would happen if this
    /// point were the identity" (constructing a transcript that a subsequent
    /// verification is expected to reject) without the append itself aborting
    /// early — the identity check still runs, its result is just discarded.
    /// Not for use outside proof `init` paths.
    pub inline fn appendNoValidate(
        self: *Transcript,
        comptime session: *Session,
        comptime t: Input.Type,
        comptime label: []const u8,
        data: @FieldType(Message, @tagName(t.base())),
    ) void {
        const input = comptime session.nextInput(
            @field(Input.Type, "validate_" ++ @tagName(t)),
            label,
        );
        data.rejectIdentity() catch {}; // ignore the error
        self.appendMessage(input.label, @unionInit(Message, @tagName(t), data));
    }

    /// Squeezes `destination.len` raw challenge bytes under `label` — Merlin's
    /// `challenge_bytes`: length-prefix the request the same way `appendBytes`
    /// length-prefixes an append (so a 32-byte and a 64-byte challenge drawn
    /// under the same label can never collide), then PRF-squeeze the sponge.
    /// Public (rather than session-gated) because `challengeScalar` needs it and
    /// tests reproduce the reference crate's raw-bytes challenge examples with
    /// it directly; production proof code should still prefer
    /// `challengeScalar`.
    pub fn challengeBytes(
        self: *Transcript,
        label: []const u8,
        destination: []u8,
    ) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(destination.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&data_len, true);
        self.strobe.prf(destination, false);
    }

    /// Draws a uniformly-distributed scalar challenge: squeeze 64 challenge
    /// bytes, then reduce mod the Ed25519 scalar field order. Must go through
    /// `reduce64` (the 10-limb wide-reduction path) and not `Scalar.fromBytes64`
    /// so the reduction matches curve25519-dalek's `Scalar::from_bytes_mod_order_wide`
    /// bit-for-bit — a narrower/differently-limbed reduction algorithm can be
    /// numerically correct mod L while still landing on different intermediate
    /// (and here, final) representative bytes.
    pub inline fn challengeScalar(
        self: *Transcript,
        comptime session: *Session,
        comptime label: []const u8,
    ) Scalar {
        const input = comptime session.nextInput(.challenge, label);
        var buffer: [64]u8 = @splat(0);
        self.challengeBytes(input.label, &buffer);
        const compressed = Ed25519.scalar.reduce64(buffer);
        return Scalar.fromBytes(compressed);
    }

    // ── domain separation helpers ───────────────────────────────────────────

    /// Appends `seperator` under the fixed "dom-sep" label. The only call site
    /// permitted to construct a `.domsep` append (see the assertion in `append`).
    pub inline fn appendDomSep(
        self: *Transcript,
        comptime session: *Session,
        comptime seperator: DomainSeperator,
    ) void {
        self.append(session, .domsep, "dom-sep", seperator);
    }

    /// Shared prefix for the two range-proof-family transcripts (the top-level
    /// range proof and its inner-product argument): domain separator followed
    /// by the bit-width `n` this instance was constructed for, so a proof sized
    /// for one `n` can never verify against a transcript built for another.
    pub inline fn appendRangeProof(
        self: *Transcript,
        comptime session: *Session,
        comptime mode: enum { range, inner },
        n: comptime_int,
    ) void {
        self.appendDomSep(session, switch (mode) {
            .range => .@"range-proof",
            .inner => .@"inner-product",
        });
        self.append(session, .u64, "n", n);
    }

    // ── protocol-contract sessions ──────────────────────────────────────────
    //
    // A `Session` is the compile-time enforcement mechanism described above at
    // `append`: each proof type defines a `Contract` (ordered list of expected
    // (label, type) pairs) once, and every `append`/`appendDomSep`/
    // `challengeScalar` call against that session advances and checks against
    // it. This exists purely to catch transcript-ordering bugs at compile time
    // — it has no effect on the bytes absorbed into Strobe.

    pub const Input = struct {
        label: []const u8,
        type: Type,
        seperator: ?DomainSeperator = null,

        const Type = enum {
            bytes,
            scalar,
            u64,

            point,
            pubkey,
            ciphertext,
            commitment,
            grouped_2,
            grouped_3,

            validate_point,
            validate_pubkey,
            validate_ciphertext,
            validate_commitment,
            validate_grouped_2,
            validate_grouped_3,

            domsep,
            challenge,

            /// Returns whether this input type performs identity validation.
            fn validates(t: Type) bool {
                return switch (t) {
                    .validate_point,
                    .validate_pubkey,
                    .validate_ciphertext,
                    .validate_commitment,
                    .validate_grouped_2,
                    .validate_grouped_3,
                    => true,
                    else => false,
                };
            }

            /// For a given input type, returns the base type.
            /// E.g. `validate_point` -> `point`
            /// E.g. `point` -> `point`
            fn base(t: Type) Type {
                if (t.validates()) {
                    return @field(Type, @tagName(t)["validate_".len..]);
                }
                return t;
            }
        };

        pub fn domain(sep: DomainSeperator) Input {
            return .{ .label = "dom-sep", .type = .domsep, .seperator = sep };
        }

        fn check(self: Input, t: Type, label: []const u8) void {
            if (self.type != t) {
                @compileError("expected: " ++ @tagName(self.type) ++ ", found: " ++ @tagName(t));
            }
            std.debug.assert(std.mem.eql(u8, self.label, label));
        }
    };

    pub const Contract = []const Input;

    pub const Session = struct {
        i: u8,
        contract: Contract,
        /// Set once an identity validation errors, so `finish` skips the
        /// "contract fully consumed" check on the (intentionally) abandoned path.
        err: bool,

        pub inline fn nextInput(comptime self: *Session, t: Input.Type, label: []const u8) Input {
            comptime {
                defer self.i += 1;
                const input = self.contract[self.i];
                input.check(t, label);
                return input;
            }
        }

        pub inline fn finish(comptime self: *Session) void {
            // For performance, certain computations (specifically in `init`
            // functions) skip the last parts of the transcript when they
            // aren't needed (e.g. the ciphertext_ciphertext proof). This check
            // still forces those extra computations to run in Debug (catching
            // a genuinely unfulfilled contract), while allowing a release
            // build to skip them.
            if (builtin.mode == .Debug and !self.err and self.i != self.contract.len) {
                @compileError("contract unfulfilled");
            }
        }

        inline fn cancel(comptime self: *Session) void {
            comptime self.err = true;
        }
    };

    /// Builds a `Session` for a `contract` that ends in a `challenge` — i.e. the
    /// normal case, where the transcript's whole purpose is to produce a
    /// Fiat-Shamir challenge at the end.
    pub inline fn getSession(comptime contract: []const Input) Session {
        comptime {
            const last_contract = contract[contract.len - 1];
            std.debug.assert(last_contract.type == .challenge);
            return .{ .i = 0, .contract = contract, .err = false };
        }
    }

    /// The same as `getSession`, but does not require the contract to end with
    /// a challenge. Only used for "init" contracts (such as
    /// `percentage_with_cap`'s) that append values without immediately drawing
    /// a challenge from them.
    pub inline fn getInitSession(comptime contract: []const Input) Session {
        comptime {
            return .{ .i = 0, .contract = contract, .err = false };
        }
    }
};

test "equivalence" {
    var transcript = Transcript.initTest("test protocol");

    comptime var session = Transcript.getSession(&.{
        .{ .label = "some label", .type = .bytes },
        .{ .label = "challenge", .type = .challenge },
    });
    transcript.append(&session, .bytes, "some label", "some data");

    var bytes: [32]u8 = undefined;
    transcript.challengeBytes("challenge", &bytes);

    try std.testing.expectEqualSlices(u8, &.{
        159, 115, 74,  116, 119, 227, 89,  42,
        108, 83,  69,  218, 43,  29,  11,  79,
        117, 141, 121, 172, 163, 50,  123, 92,
        25,  21,  111, 177, 11,  232, 4,   35,
    }, &bytes);
}
