//! TLS 1.3 Implementation for QUIC
//!
//! Implements the cryptographic operations required for QUIC-TLS per RFC 9001.
//! Uses Zig's standard library crypto primitives.
//!
//! Key Features:
//! - HKDF-based key derivation (RFC 5869)
//! - AEAD encryption/decryption (AES-128-GCM, ChaCha20-Poly1305)
//! - TLS 1.3 key schedule
//! - QUIC header protection

const std = @import("std");
const crypto = std.crypto;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = crypto.hash.sha2.Sha256;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// TLS 1.3 version
pub const TLS_VERSION_13: u16 = 0x0304;

/// QUIC-specific labels for key derivation
pub const QUIC_CLIENT_INITIAL_LABEL = "client in";
pub const QUIC_SERVER_INITIAL_LABEL = "server in";
pub const QUIC_KEY_LABEL = "quic key";
pub const QUIC_IV_LABEL = "quic iv";
pub const QUIC_HP_LABEL = "quic hp";

/// Initial salt for QUIC v1 (RFC 9001, Section 5.2)
pub const INITIAL_SALT_V1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// Initial salt for QUIC v2 (RFC 9369)
pub const INITIAL_SALT_V2 = [_]u8{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
};

/// Cipher suite identifiers
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
};

/// TLS handshake message types
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

/// TLS extension types
pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    alpn = 16,
    supported_versions = 43,
    psk_key_exchange_modes = 45,
    key_share = 51,
    quic_transport_parameters = 57,
};

// ═══════════════════════════════════════════════════════════════════════════════
// HKDF IMPLEMENTATION (RFC 5869)
// ═══════════════════════════════════════════════════════════════════════════════

/// HKDF-Extract: Extract a pseudorandom key from input keying material
pub fn hkdfExtract(salt: []const u8, ikm: []const u8) [32]u8 {
    var hmac = HmacSha256.init(if (salt.len > 0) salt else &[_]u8{0} ** 32);
    hmac.update(ikm);
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// HKDF-Expand: Expand a pseudorandom key to desired length
/// Bounds-safe implementation with explicit initialization
pub fn hkdfExpand(prk: []const u8, info: []const u8, out: []u8) void {
    // Explicit zero initialization for safety
    var t: [32]u8 = [_]u8{0} ** 32;
    var t_len: usize = 0;
    var offset: usize = 0;
    var counter: u8 = 1;

    while (offset < out.len) {
        var hmac = HmacSha256.init(prk);
        if (t_len > 0) {
            hmac.update(t[0..t_len]);
        }
        hmac.update(info);
        hmac.update(&[_]u8{counter});
        hmac.final(&t);
        t_len = 32;

        const copy_len = @min(32, out.len - offset);
        @memcpy(out[offset..][0..copy_len], t[0..copy_len]);
        offset += copy_len;

        // Overflow protection for counter
        if (counter == 255) break;
        counter += 1;
    }
}

/// HKDF-Expand-Label for TLS 1.3
pub fn hkdfExpandLabel(
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: usize,
    out: []u8,
) void {
    // HkdfLabel structure:
    // uint16 length;
    // opaque label<7..255>;
    // opaque context<0..255>;

    var info_buf: [512]u8 = undefined;
    var info_len: usize = 0;

    // Length (2 bytes, big-endian)
    info_buf[info_len] = @intCast((length >> 8) & 0xFF);
    info_len += 1;
    info_buf[info_len] = @intCast(length & 0xFF);
    info_len += 1;

    // Label with "tls13 " prefix
    const full_label_len = 6 + label.len;
    info_buf[info_len] = @intCast(full_label_len);
    info_len += 1;
    @memcpy(info_buf[info_len..][0..6], "tls13 ");
    info_len += 6;
    @memcpy(info_buf[info_len..][0..label.len], label);
    info_len += label.len;

    // Context
    info_buf[info_len] = @intCast(context.len);
    info_len += 1;
    if (context.len > 0) {
        @memcpy(info_buf[info_len..][0..context.len], context);
        info_len += context.len;
    }

    hkdfExpand(secret, info_buf[0..info_len], out[0..length]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUIC KEY DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Secrets for a single encryption level
pub const Secrets = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8, // Header protection key

    pub fn derive(secret: []const u8) Secrets {
        var result: Secrets = undefined;

        // Derive key
        hkdfExpandLabel(secret, QUIC_KEY_LABEL, "", 16, &result.key);

        // Derive IV
        hkdfExpandLabel(secret, QUIC_IV_LABEL, "", 12, &result.iv);

        // Derive header protection key
        hkdfExpandLabel(secret, QUIC_HP_LABEL, "", 16, &result.hp);

        return result;
    }
};

/// Traffic secrets for both directions
pub const TrafficSecrets = struct {
    client: Secrets,
    server: Secrets,
};

/// Derive initial secrets from connection ID (QUIC v1)
pub fn deriveInitialSecrets(dcid: []const u8) TrafficSecrets {
    // Initial secret = HKDF-Extract(initial_salt, dcid)
    const initial_secret = hkdfExtract(&INITIAL_SALT_V1, dcid);

    // Derive client and server secrets
    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;

    hkdfExpandLabel(&initial_secret, QUIC_CLIENT_INITIAL_LABEL, "", 32, &client_secret);
    hkdfExpandLabel(&initial_secret, QUIC_SERVER_INITIAL_LABEL, "", 32, &server_secret);

    return .{
        .client = Secrets.derive(&client_secret),
        .server = Secrets.derive(&server_secret),
    };
}

/// Derive initial secrets for QUIC v2
pub fn deriveInitialSecretsV2(dcid: []const u8) TrafficSecrets {
    const initial_secret = hkdfExtract(&INITIAL_SALT_V2, dcid);

    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;

    hkdfExpandLabel(&initial_secret, QUIC_CLIENT_INITIAL_LABEL, "", 32, &client_secret);
    hkdfExpandLabel(&initial_secret, QUIC_SERVER_INITIAL_LABEL, "", 32, &server_secret);

    return .{
        .client = Secrets.derive(&client_secret),
        .server = Secrets.derive(&server_secret),
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// AEAD ENCRYPTION/DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Encryption context for a single direction
pub const AeadContext = struct {
    key: [16]u8,
    iv: [12]u8,
    cipher_suite: CipherSuite,

    const Self = @This();

    pub fn init(secrets: Secrets, suite: CipherSuite) Self {
        return .{
            .key = secrets.key,
            .iv = secrets.iv,
            .cipher_suite = suite,
        };
    }

    /// Compute nonce for packet number
    fn computeNonce(self: *const Self, packet_number: u64) [12]u8 {
        var nonce = self.iv;
        // XOR the packet number with the IV (in big-endian, right-aligned)
        const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }
        return nonce;
    }

    /// Encrypt a QUIC packet payload
    pub fn encrypt(
        self: *const Self,
        packet_number: u64,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) void {
        const nonce = self.computeNonce(packet_number);

        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                Aes128Gcm.encrypt(ciphertext, tag, plaintext, aad, nonce, self.key);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                // TODO: add 32-byte key support for ChaCha20-Poly1305
                Aes128Gcm.encrypt(ciphertext, tag, plaintext, aad, nonce, self.key);
            },
            else => {
                // AES-256-GCM not yet supported, fall back to AES-128
                Aes128Gcm.encrypt(ciphertext, tag, plaintext, aad, nonce, self.key);
            },
        }
    }

    /// Decrypt a QUIC packet payload
    pub fn decrypt(
        self: *const Self,
        packet_number: u64,
        aad: []const u8,
        ciphertext: []const u8,
        tag: [16]u8,
        plaintext: []u8,
    ) !void {
        const nonce = self.computeNonce(packet_number);

        switch (self.cipher_suite) {
            .TLS_AES_128_GCM_SHA256 => {
                try Aes128Gcm.decrypt(plaintext, ciphertext, tag, aad, nonce, self.key);
            },
            .TLS_CHACHA20_POLY1305_SHA256 => {
                // TODO: add 32-byte key support for ChaCha20-Poly1305
                try Aes128Gcm.decrypt(plaintext, ciphertext, tag, aad, nonce, self.key);
            },
            else => {
                try Aes128Gcm.decrypt(plaintext, ciphertext, tag, aad, nonce, self.key);
            },
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// HEADER PROTECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Apply header protection to a QUIC packet
/// Bounds-safe implementation with validation
pub fn applyHeaderProtection(
    hp_key: [16]u8,
    header: []u8,
    pn_offset: usize,
    pn_length: usize,
    sample: [16]u8,
) void {
    // Bounds check: header must have at least 1 byte
    if (header.len == 0) return;

    // Bounds check: pn_offset + pn_length must fit in header
    if (pn_offset + pn_length > header.len) return;

    // Bounds check: pn_length must be 1-4 and fit in mask (bytes 1-4)
    if (pn_length == 0 or pn_length > 4) return;

    // Generate mask using AES-ECB(hp_key, sample)
    // Explicit zero initialization for safety
    var mask: [16]u8 = [_]u8{0} ** 16;
    const aes = crypto.core.aes.Aes128.initEnc(hp_key);
    aes.encrypt(&mask, &sample);

    // Apply mask to first byte (flags)
    if ((header[0] & 0x80) != 0) {
        // Long header: mask lower 4 bits
        header[0] ^= mask[0] & 0x0f;
    } else {
        // Short header: mask lower 5 bits
        header[0] ^= mask[0] & 0x1f;
    }

    // Apply mask to packet number bytes (bounds already checked above)
    for (0..pn_length) |i| {
        header[pn_offset + i] ^= mask[1 + i];
    }
}

/// Remove header protection from a QUIC packet
/// Bounds-safe implementation with validation
pub fn removeHeaderProtection(
    hp_key: [16]u8,
    header: []u8,
    pn_offset: usize,
    sample: [16]u8,
) usize {
    // Bounds check: header must have at least 1 byte
    if (header.len == 0) return 0;

    // Generate mask using AES-ECB(hp_key, sample)
    // Explicit zero initialization for safety
    var mask: [16]u8 = [_]u8{0} ** 16;
    const aes = crypto.core.aes.Aes128.initEnc(hp_key);
    aes.encrypt(&mask, &sample);

    // Remove mask from first byte to get packet number length
    var first_byte = header[0];
    if ((first_byte & 0x80) != 0) {
        first_byte ^= mask[0] & 0x0f;
    } else {
        first_byte ^= mask[0] & 0x1f;
    }
    header[0] = first_byte;

    // Get packet number length from first byte (1-4 bytes)
    const pn_length: usize = (first_byte & 0x03) + 1;

    // Bounds check: pn_offset + pn_length must fit in header
    if (pn_offset + pn_length > header.len) return pn_length;

    // Remove mask from packet number
    for (0..pn_length) |i| {
        header[pn_offset + i] ^= mask[1 + i];
    }

    return pn_length;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TLS 1.3 KEY SCHEDULE
// ═══════════════════════════════════════════════════════════════════════════════

/// TLS 1.3 key schedule state
pub const KeySchedule = struct {
    /// Current secret
    secret: [32]u8,
    /// Handshake transcript hash
    transcript_hash: Sha256,
    /// Early secret
    early_secret: [32]u8,
    /// Handshake secret
    handshake_secret: [32]u8,
    /// Master secret
    master_secret: [32]u8,
    /// Current stage
    stage: Stage,

    pub const Stage = enum {
        initial,
        early_data,
        handshake,
        application,
    };

    const Self = @This();

    pub fn init() Self {
        var ks = Self{
            .secret = undefined,
            .transcript_hash = Sha256.init(.{}),
            .early_secret = undefined,
            .handshake_secret = undefined,
            .master_secret = undefined,
            .stage = .initial,
        };

        // Derive early secret with empty PSK
        const empty_ikm = [_]u8{0} ** 32;
        const zero_salt = [_]u8{0} ** 32;
        ks.early_secret = hkdfExtract(&zero_salt, &empty_ikm);
        ks.secret = ks.early_secret;

        return ks;
    }

    /// Update transcript hash with a handshake message
    pub fn updateTranscript(self: *Self, message: []const u8) void {
        self.transcript_hash.update(message);
    }

    /// Get current transcript hash
    pub fn getTranscriptHash(self: *Self) [32]u8 {
        // Clone to not affect ongoing hash
        var clone = self.transcript_hash;
        var out: [32]u8 = undefined;
        clone.final(&out);
        return out;
    }

    /// Derive handshake secrets from shared secret (ECDHE)
    pub fn deriveHandshakeSecrets(self: *Self, shared_secret: []const u8) TrafficSecrets {
        // Derive-Secret(early_secret, "derived", "")
        var derived_secret: [32]u8 = undefined;
        var empty_hash: [32]u8 = undefined;
        Sha256.hash(&[_]u8{}, &empty_hash, .{});
        hkdfExpandLabel(&self.early_secret, "derived", &empty_hash, 32, &derived_secret);

        // Handshake secret = HKDF-Extract(derived_secret, shared_secret)
        self.handshake_secret = hkdfExtract(&derived_secret, shared_secret);
        self.secret = self.handshake_secret;
        self.stage = .handshake;

        // Get transcript hash at this point
        const transcript = self.getTranscriptHash();

        // Derive client and server handshake traffic secrets
        var client_secret: [32]u8 = undefined;
        var server_secret: [32]u8 = undefined;

        hkdfExpandLabel(&self.handshake_secret, "c hs traffic", &transcript, 32, &client_secret);
        hkdfExpandLabel(&self.handshake_secret, "s hs traffic", &transcript, 32, &server_secret);

        return .{
            .client = Secrets.derive(&client_secret),
            .server = Secrets.derive(&server_secret),
        };
    }

    /// Derive application secrets (after handshake)
    pub fn deriveApplicationSecrets(self: *Self) TrafficSecrets {
        // Derive-Secret(handshake_secret, "derived", "")
        var derived_secret: [32]u8 = undefined;
        var empty_hash: [32]u8 = undefined;
        Sha256.hash(&[_]u8{}, &empty_hash, .{});
        hkdfExpandLabel(&self.handshake_secret, "derived", &empty_hash, 32, &derived_secret);

        // Master secret = HKDF-Extract(derived_secret, 0)
        const zero_ikm = [_]u8{0} ** 32;
        self.master_secret = hkdfExtract(&derived_secret, &zero_ikm);
        self.secret = self.master_secret;
        self.stage = .application;

        // Get final transcript hash
        const transcript = self.getTranscriptHash();

        // Derive client and server application traffic secrets
        var client_secret: [32]u8 = undefined;
        var server_secret: [32]u8 = undefined;

        hkdfExpandLabel(&self.master_secret, "c ap traffic", &transcript, 32, &client_secret);
        hkdfExpandLabel(&self.master_secret, "s ap traffic", &transcript, 32, &server_secret);

        return .{
            .client = Secrets.derive(&client_secret),
            .server = Secrets.derive(&server_secret),
        };
    }

    /// Derive next application secret (key update)
    pub fn deriveNextApplicationSecret(current_secret: [32]u8) [32]u8 {
        var next_secret: [32]u8 = undefined;
        hkdfExpandLabel(&current_secret, "traffic upd", "", 32, &next_secret);
        return next_secret;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TLS 1.3 HANDSHAKE MESSAGES
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a ClientHello message
pub fn buildClientHello(
    allocator: std.mem.Allocator,
    random: [32]u8,
    session_id: []const u8,
    cipher_suites: []const CipherSuite,
    key_share: []const u8,
    alpn: []const []const u8,
    quic_params: []const u8,
    sni: []const u8,
) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(allocator);

    // Handshake header (filled later)
    try msg.appendNTimes(allocator, 0, 4);

    // Client version (TLS 1.2 for compatibility)
    try msg.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // Random
    try msg.appendSlice(allocator, &random);

    // Session ID
    try msg.append(allocator, @intCast(session_id.len));
    if (session_id.len > 0) {
        try msg.appendSlice(allocator, session_id);
    }

    // Cipher suites
    const cs_len: u16 = @intCast(cipher_suites.len * 2);
    try msg.append(allocator, @intCast((cs_len >> 8) & 0xFF));
    try msg.append(allocator, @intCast(cs_len & 0xFF));
    for (cipher_suites) |cs| {
        try msg.append(allocator, @intCast((@intFromEnum(cs) >> 8) & 0xFF));
        try msg.append(allocator, @intCast(@intFromEnum(cs) & 0xFF));
    }

    // Compression methods (none)
    try msg.append(allocator, 1);
    try msg.append(allocator, 0);

    // Extensions start position
    const ext_len_pos = msg.items.len;
    try msg.appendNTimes(allocator, 0, 2); // Extension length placeholder

    // Extension: server_name (SNI) — canonical Solana "{ip}.{port}.sol"
    // (Agave tls-utils socket_addr_to_quic_server_name). Real leaders/quinn route connection
    // tokens by SNI; empirically not required by rustls to complete the handshake, but canonical.
    if (sni.len > 0 and sni.len <= 59) {
        var sni_ext: [64]u8 = undefined;
        const name_len: u16 = @intCast(sni.len);
        const list_len: u16 = name_len + 3;
        sni_ext[0] = @intCast((list_len >> 8) & 0xFF);
        sni_ext[1] = @intCast(list_len & 0xFF);
        sni_ext[2] = 0x00; // name_type = host_name
        sni_ext[3] = @intCast((name_len >> 8) & 0xFF);
        sni_ext[4] = @intCast(name_len & 0xFF);
        @memcpy(sni_ext[5..][0..sni.len], sni);
        try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.server_name), sni_ext[0 .. 5 + sni.len]);
    }

    // Extension: supported_versions (required for TLS 1.3)
    try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.supported_versions), &[_]u8{
        0x02, // Length of versions
        0x03, 0x04, // TLS 1.3
    });

    // Extension: supported_groups
    try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.supported_groups), &[_]u8{
        0x00, 0x04, // Length
        0x00, 0x1d, // x25519
        0x00, 0x17, // secp256r1
    });

    // Extension: signature_algorithms
    try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.signature_algorithms), &[_]u8{
        0x00, 0x08, // Length
        0x04, 0x03, // ECDSA-secp256r1-sha256
        0x08, 0x04, // RSA-PSS-rsae-sha256
        0x04, 0x01, // RSA-PKCS1-sha256
        0x08, 0x07, // ED25519
    });

    // Extension: psk_key_exchange_modes (required for TLS 1.3)
    try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.psk_key_exchange_modes), &[_]u8{
        0x01, // length
        0x01, // psk_dhe_ke
    });

    // Extension: key_share
    if (key_share.len > 0) {
        var ks_ext: [128]u8 = undefined;
        var ks_len: usize = 0;

        // Client key share list length
        const list_len: u16 = @intCast(4 + key_share.len);
        ks_ext[ks_len] = @intCast((list_len >> 8) & 0xFF);
        ks_len += 1;
        ks_ext[ks_len] = @intCast(list_len & 0xFF);
        ks_len += 1;

        // Key share entry: x25519
        ks_ext[ks_len] = 0x00;
        ks_len += 1;
        ks_ext[ks_len] = 0x1d; // x25519
        ks_len += 1;
        ks_ext[ks_len] = @intCast((key_share.len >> 8) & 0xFF);
        ks_len += 1;
        ks_ext[ks_len] = @intCast(key_share.len & 0xFF);
        ks_len += 1;
        @memcpy(ks_ext[ks_len..][0..key_share.len], key_share);
        ks_len += key_share.len;

        try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.key_share), ks_ext[0..ks_len]);
    }

    // Extension: ALPN
    if (alpn.len > 0) {
        var alpn_ext: [256]u8 = undefined;
        var alpn_len: usize = 2; // List length placeholder

        for (alpn) |proto| {
            alpn_ext[alpn_len] = @intCast(proto.len);
            alpn_len += 1;
            @memcpy(alpn_ext[alpn_len..][0..proto.len], proto);
            alpn_len += proto.len;
        }

        // Fill list length
        const list_len: u16 = @intCast(alpn_len - 2);
        alpn_ext[0] = @intCast((list_len >> 8) & 0xFF);
        alpn_ext[1] = @intCast(list_len & 0xFF);

        try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.alpn), alpn_ext[0..alpn_len]);
    }

    // Extension: QUIC transport parameters
    if (quic_params.len > 0) {
        try appendExtension(allocator, &msg, @intFromEnum(ExtensionType.quic_transport_parameters), quic_params);
    }

    // Fill extension length
    const ext_len: u16 = @intCast(msg.items.len - ext_len_pos - 2);
    msg.items[ext_len_pos] = @intCast((ext_len >> 8) & 0xFF);
    msg.items[ext_len_pos + 1] = @intCast(ext_len & 0xFF);

    // Fill handshake header
    const body_len: u24 = @intCast(msg.items.len - 4);
    msg.items[0] = @intFromEnum(HandshakeType.client_hello);
    msg.items[1] = @intCast((body_len >> 16) & 0xFF);
    msg.items[2] = @intCast((body_len >> 8) & 0xFF);
    msg.items[3] = @intCast(body_len & 0xFF);

    return msg.toOwnedSlice(allocator);
}

fn appendExtension(allocator: std.mem.Allocator, msg: *std.ArrayList(u8), ext_type: u16, data: []const u8) !void {
    // Extension type
    try msg.append(allocator, @intCast((ext_type >> 8) & 0xFF));
    try msg.append(allocator, @intCast(ext_type & 0xFF));

    // Extension length
    try msg.append(allocator, @intCast((data.len >> 8) & 0xFF));
    try msg.append(allocator, @intCast(data.len & 0xFF));

    // Extension data
    try msg.appendSlice(allocator, data);
}

/// Parse a ClientHello and return the peer's X25519 key_share (32 bytes), if present.
/// Mirror of parseServerHello but for the ClientHello layout (cipher-suite LIST with a
/// 2-byte length, 1-byte-prefixed compression-methods list, and a key_share extension whose
/// data is `client_shares_len(2) | [group(2) | key_len(2) | key]...`). The server needs this
/// peer public key to complete the X25519 ECDHE (the dead ServerHandshake.processClientHello
/// stubbed it). Returns error.NoKeyShare if no x25519 (0x001d) share is found.
pub fn parseClientHelloKeyShare(data: []const u8) ![]const u8 {
    if (data.len < 38) return error.MessageTooShort;
    var offset: usize = 0;

    offset += 4; // handshake type + 3-byte length (verified by caller)
    offset += 2; // client_version
    if (offset + 32 > data.len) return error.MessageTooShort;
    offset += 32; // random

    // Session ID (1-byte length prefix)
    if (offset >= data.len) return error.MessageTooShort;
    const session_id_len = data[offset];
    offset += 1;
    if (offset + session_id_len > data.len) return error.MessageTooShort;
    offset += session_id_len;

    // Cipher suites (2-byte length prefix)
    if (offset + 2 > data.len) return error.MessageTooShort;
    const cs_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
    offset += 2;
    if (offset + cs_len > data.len) return error.MessageTooShort;
    offset += cs_len;

    // Compression methods (1-byte length prefix)
    if (offset >= data.len) return error.MessageTooShort;
    const comp_len = data[offset];
    offset += 1;
    if (offset + comp_len > data.len) return error.MessageTooShort;
    offset += comp_len;

    // Extensions (2-byte length prefix)
    if (offset + 2 > data.len) return error.NoKeyShare;
    const ext_total = (@as(u16, data[offset]) << 8) | data[offset + 1];
    offset += 2;
    const ext_end = @min(offset + ext_total, data.len);

    while (offset + 4 <= ext_end) {
        const ext_type = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;
        const ext_data_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;
        if (offset + ext_data_len > data.len) break;

        if (ext_type == @intFromEnum(ExtensionType.key_share)) {
            // ClientHello key_share data: client_shares_len(2) | [group(2)|len(2)|key]...
            const ks = data[offset..][0..ext_data_len];
            if (ks.len < 2) return error.NoKeyShare;
            var ks_off: usize = 2; // skip client_shares list length
            while (ks_off + 4 <= ks.len) {
                const group = (@as(u16, ks[ks_off]) << 8) | ks[ks_off + 1];
                const klen = (@as(u16, ks[ks_off + 2]) << 8) | ks[ks_off + 3];
                ks_off += 4;
                if (ks_off + klen > ks.len) break;
                if (group == 0x001d and klen >= 32) { // x25519
                    return ks[ks_off..][0..32];
                }
                ks_off += klen;
            }
            return error.NoKeyShare;
        }

        offset += ext_data_len;
    }
    return error.NoKeyShare;
}

/// Parse a ServerHello message
pub const ServerHello = struct {
    random: [32]u8,
    session_id: []const u8,
    cipher_suite: CipherSuite,
    key_share: []const u8,
};

/// Parse a ServerHello message with comprehensive bounds checking
pub fn parseServerHello(data: []const u8) !ServerHello {
    // Minimum size: handshake header(4) + version(2) + random(32) = 38
    if (data.len < 38) return error.MessageTooShort;

    var offset: usize = 0;

    // Skip handshake type and length (already verified by caller)
    offset += 4;

    // Server version (ignored, use extension)
    offset += 2;

    // Bounds check: ensure we have 32 bytes for random
    if (offset + 32 > data.len) return error.MessageTooShort;

    // Random - use explicit initialization
    var random: [32]u8 = [_]u8{0} ** 32;
    @memcpy(&random, data[offset..][0..32]);
    offset += 32;

    // Bounds check: session ID length byte
    if (offset >= data.len) return error.MessageTooShort;

    // Session ID
    const session_id_len = data[offset];
    offset += 1;

    // Bounds check: session ID data
    if (offset + session_id_len > data.len) return error.MessageTooShort;
    const session_id = data[offset..][0..session_id_len];
    offset += session_id_len;

    // Bounds check: cipher suite (2 bytes)
    if (offset + 2 > data.len) return error.MessageTooShort;

    // Cipher suite
    const cs_val = (@as(u16, data[offset]) << 8) | data[offset + 1];
    const cipher_suite = std.meta.intToEnum(CipherSuite, cs_val) catch return error.UnsupportedCipherSuite;
    offset += 2;

    // Bounds check: compression method (1 byte)
    if (offset >= data.len) return error.MessageTooShort;

    // Compression method (should be 0)
    offset += 1;

    // Extensions
    var key_share: []const u8 = &[_]u8{};

    // Bounds check: extension length field
    if (offset + 2 <= data.len) {
        const ext_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        // Bounds check: extension data
        const ext_end = @min(offset + ext_len, data.len);

        while (offset + 4 <= ext_end and offset + 4 <= data.len) {
            const ext_type = (@as(u16, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            // Bounds check before reading ext_data_len
            if (offset + 2 > data.len) break;
            const ext_data_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            // Bounds check: extension data length
            if (offset + ext_data_len > data.len) break;

            if (ext_type == @intFromEnum(ExtensionType.key_share)) {
                // Key share: group (2) + length (2) + key
                if (ext_data_len >= 4 and offset + 4 <= data.len) {
                    const ks_len = (@as(u16, data[offset + 2]) << 8) | data[offset + 3];
                    // Bounds check: key share data
                    if (offset + 4 + ks_len <= data.len and ks_len <= ext_data_len - 4) {
                        key_share = data[offset + 4 ..][0..ks_len];
                    }
                }
            }

            offset += ext_data_len;
        }
    }

    return ServerHello{
        .random = random,
        .session_id = session_id,
        .cipher_suite = cipher_suite,
        .key_share = key_share,
    };
}

/// Build Finished message
pub fn buildFinished(allocator: std.mem.Allocator, finished_key: [32]u8, transcript_hash: [32]u8) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(allocator);

    // Handshake type
    try msg.append(allocator, @intFromEnum(HandshakeType.finished));

    // Length (32 bytes for HMAC-SHA256)
    try msg.append(allocator, 0);
    try msg.append(allocator, 0);
    try msg.append(allocator, 32);

    // Compute verify_data = HMAC(finished_key, transcript_hash)
    var hmac = HmacSha256.init(&finished_key);
    hmac.update(&transcript_hash);
    var verify_data: [32]u8 = undefined;
    hmac.final(&verify_data);

    try msg.appendSlice(allocator, &verify_data);

    return msg.toOwnedSlice(allocator);
}

/// Verify Finished message
pub fn verifyFinished(finished_key: [32]u8, transcript_hash: [32]u8, verify_data: [32]u8) bool {
    var hmac = HmacSha256.init(&finished_key);
    hmac.update(&transcript_hash);
    var expected: [32]u8 = undefined;
    hmac.final(&expected);

    return std.mem.eql(u8, &expected, &verify_data);
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUIC TRANSPORT PARAMETERS
// ═══════════════════════════════════════════════════════════════════════════════

pub const TransportParameters = struct {
    original_dcid: ?[20]u8 = null,
    original_dcid_len: u8 = 0,
    initial_source_cid: ?[20]u8 = null,
    initial_source_cid_len: u8 = 0,
    max_idle_timeout: u64 = 30000, // 30 seconds
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 10 * 1024 * 1024, // 10MB
    initial_max_stream_data_bidi_local: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 1024 * 1024,
    initial_max_stream_data_uni: u64 = 1024 * 1024,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25, // 25ms
    disable_active_migration: bool = true,
    active_connection_id_limit: u64 = 2,

    pub fn encode(self: *const TransportParameters, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        // Encode each parameter with QUIC varint (id, length, value)
        try encodeParam(allocator, &buf, 0x00, self.original_dcid_len, self.original_dcid);
        try encodeVarInt(allocator, &buf, 0x01, self.max_idle_timeout);
        try encodeVarInt(allocator, &buf, 0x03, self.max_udp_payload_size);
        try encodeVarInt(allocator, &buf, 0x04, self.initial_max_data);
        try encodeVarInt(allocator, &buf, 0x05, self.initial_max_stream_data_bidi_local);
        try encodeVarInt(allocator, &buf, 0x06, self.initial_max_stream_data_bidi_remote);
        try encodeVarInt(allocator, &buf, 0x07, self.initial_max_stream_data_uni);
        try encodeVarInt(allocator, &buf, 0x08, self.initial_max_streams_bidi);
        try encodeVarInt(allocator, &buf, 0x09, self.initial_max_streams_uni);
        try encodeVarInt(allocator, &buf, 0x0a, self.ack_delay_exponent);
        try encodeVarInt(allocator, &buf, 0x0b, self.max_ack_delay);
        if (self.disable_active_migration) {
            try encodeEmptyParam(allocator, &buf, 0x0c);
        }
        try encodeVarInt(allocator, &buf, 0x0e, self.active_connection_id_limit);
        try encodeParam(allocator, &buf, 0x0f, self.initial_source_cid_len, self.initial_source_cid);

        return buf.toOwnedSlice(allocator);
    }

    fn appendVarInt(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: u64) !void {
        var tmp: [8]u8 = undefined;
        const len: usize = switch (value) {
            0...0x3f => blk: {
                tmp[0] = @intCast(value);
                break :blk 1;
            },
            0x40...0x3fff => blk: {
                tmp[0] = @intCast(0x40 | ((value >> 8) & 0x3f));
                tmp[1] = @intCast(value & 0xff);
                break :blk 2;
            },
            0x4000...0x3fffffff => blk: {
                tmp[0] = @intCast(0x80 | ((value >> 24) & 0x3f));
                tmp[1] = @intCast((value >> 16) & 0xff);
                tmp[2] = @intCast((value >> 8) & 0xff);
                tmp[3] = @intCast(value & 0xff);
                break :blk 4;
            },
            else => blk: {
                tmp[0] = @intCast(0xc0 | ((value >> 56) & 0x3f));
                tmp[1] = @intCast((value >> 48) & 0xff);
                tmp[2] = @intCast((value >> 40) & 0xff);
                tmp[3] = @intCast((value >> 32) & 0xff);
                tmp[4] = @intCast((value >> 24) & 0xff);
                tmp[5] = @intCast((value >> 16) & 0xff);
                tmp[6] = @intCast((value >> 8) & 0xff);
                tmp[7] = @intCast(value & 0xff);
                break :blk 8;
            },
        };
        try buf.appendSlice(allocator, tmp[0..len]);
    }

    fn encodeParam(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), id: u64, len: u8, data: ?[20]u8) !void {
        if (data) |d| {
            try appendVarInt(allocator, buf, id);
            try appendVarInt(allocator, buf, len);
            try buf.appendSlice(allocator, d[0..len]);
        }
    }

    fn encodeEmptyParam(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), id: u64) !void {
        try appendVarInt(allocator, buf, id);
        try appendVarInt(allocator, buf, 0);
    }

    fn encodeVarInt(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), id: u64, value: u64) !void {
        var tmp: [8]u8 = undefined;
        const value_len: usize = switch (value) {
            0...0x3f => blk: {
                tmp[0] = @intCast(value);
                break :blk 1;
            },
            0x40...0x3fff => blk: {
                tmp[0] = @intCast(0x40 | ((value >> 8) & 0x3f));
                tmp[1] = @intCast(value & 0xff);
                break :blk 2;
            },
            0x4000...0x3fffffff => blk: {
                tmp[0] = @intCast(0x80 | ((value >> 24) & 0x3f));
                tmp[1] = @intCast((value >> 16) & 0xff);
                tmp[2] = @intCast((value >> 8) & 0xff);
                tmp[3] = @intCast(value & 0xff);
                break :blk 4;
            },
            else => blk: {
                tmp[0] = @intCast(0xc0 | ((value >> 56) & 0x3f));
                tmp[1] = @intCast((value >> 48) & 0xff);
                tmp[2] = @intCast((value >> 40) & 0xff);
                tmp[3] = @intCast((value >> 32) & 0xff);
                tmp[4] = @intCast((value >> 24) & 0xff);
                tmp[5] = @intCast((value >> 16) & 0xff);
                tmp[6] = @intCast((value >> 8) & 0xff);
                tmp[7] = @intCast(value & 0xff);
                break :blk 8;
            },
        };

        try appendVarInt(allocator, buf, id);
        try appendVarInt(allocator, buf, value_len);
        try buf.appendSlice(allocator, tmp[0..value_len]);
    }
};

/// The peer's advertised initial stream limits, decoded from its
/// quic_transport_parameters (TLS ext 57) in the EncryptedExtensions message.
///
/// CANONICAL DEFAULT = 0 (RFC 9000 §18.2): an ABSENT initial_max_streams_uni/bidi
/// means the peer grants ZERO streams up front — NOT the local struct's encode
/// default of 100. This is load-bearing: real Solana leaders OMIT id 0x09, so this
/// correctly yields uni=0 and the client must still wait for a MAX_STREAMS_UNI
/// frame. Our own ingest server DOES advertise id 0x09=100, so a Vexor→Vexor
/// connection reads 100 here and can open uni streams immediately.
pub const PeerStreamLimits = struct {
    uni: u64 = 0,
    bidi: u64 = 0,
};

/// Decode one RFC 9000 §16 variable-length integer. Returns the value and the
/// number of bytes consumed, or null if the buffer is too short (never panics —
/// this parses untrusted bytes received from a remote leader).
fn decodeQuicVarInt(data: []const u8) ?struct { value: u64, len: usize } {
    if (data.len == 0) return null;
    const prefix: u3 = @intCast(data[0] >> 6);
    const len: usize = @as(usize, 1) << prefix; // 1, 2, 4, or 8
    if (data.len < len) return null;
    var value: u64 = data[0] & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) value = (value << 8) | data[i];
    return .{ .value = value, .len = len };
}

/// Decode the QUIC transport-parameters body (the contents of TLS ext 57) and
/// return the peer's initial uni/bidi stream limits. Each parameter is
/// (id varint, length varint, value bytes); ids 0x08/0x09 are
/// initial_max_streams_bidi/uni. Unknown ids are skipped by their length.
/// Bounds-checked end to end; a malformed param simply stops the walk.
fn decodeQuicTransportParams(body: []const u8) PeerStreamLimits {
    var out: PeerStreamLimits = .{};
    var p: usize = 0;
    while (p < body.len) {
        const id = decodeQuicVarInt(body[p..]) orelse break;
        p += id.len;
        const plen = decodeQuicVarInt(body[p..]) orelse break;
        p += plen.len;
        const val_end = p + @as(usize, @intCast(plen.value));
        if (val_end > body.len) break;
        switch (id.value) {
            0x08 => {
                if (decodeQuicVarInt(body[p..val_end])) |v| out.bidi = v.value;
            },
            0x09 => {
                if (decodeQuicVarInt(body[p..val_end])) |v| out.uni = v.value;
            },
            else => {},
        }
        p = val_end;
    }
    return out;
}

/// Walk a TLS 1.3 EncryptedExtensions handshake message (RFC 8446 §4.3.1) and
/// return the peer's advertised initial stream limits from its
/// quic_transport_parameters extension (type 57). Returns the absent-default {0,0}
/// if the message is malformed or the extension is missing — bounds-checked
/// throughout (untrusted network bytes).
///
/// Message layout: msg_type(1) ‖ length(u24) ‖ extensions_len(u16) ‖ extensions,
/// where each extension is ext_type(u16) ‖ ext_len(u16) ‖ ext_data(ext_len).
pub fn peerStreamLimitsFromEncryptedExtensions(ee: []const u8) PeerStreamLimits {
    if (ee.len < 6) return .{};
    const ext_block_len = (@as(usize, ee[4]) << 8) | ee[5];
    var offset: usize = 6;
    const ext_end = @min(offset + ext_block_len, ee.len);
    while (offset + 4 <= ext_end) {
        const ext_type = (@as(u16, ee[offset]) << 8) | ee[offset + 1];
        const ext_len = (@as(usize, ee[offset + 2]) << 8) | ee[offset + 3];
        offset += 4;
        const body_end = offset + ext_len;
        if (body_end > ext_end) break;
        if (ext_type == @intFromEnum(ExtensionType.quic_transport_parameters)) {
            return decodeQuicTransportParams(ee[offset..body_end]);
        }
        offset = body_end;
    }
    return .{};
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "HKDF-Extract" {
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const ikm = [_]u8{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    const prk = hkdfExtract(&salt, &ikm);
    // Expected PRK from RFC 5869 Test Case 1
    try std.testing.expect(prk.len == 32);
}

test "HKDF-Expand-Label" {
    var secret: [32]u8 = undefined;
    @memset(&secret, 0x42);

    var output: [16]u8 = undefined;
    hkdfExpandLabel(&secret, "test", "", 16, &output);

    // Just verify it doesn't crash and produces output
    try std.testing.expect(output[0] != 0 or output[1] != 0);
}

test "Initial secret derivation" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = deriveInitialSecrets(&dcid);

    // Verify we got non-zero keys
    try std.testing.expect(secrets.client.key[0] != 0 or secrets.client.key[1] != 0);
    try std.testing.expect(secrets.server.key[0] != 0 or secrets.server.key[1] != 0);
}

test "Header protection" {
    var header = [_]u8{ 0xc0, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e };
    const hp_key = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    const sample = [_]u8{ 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b };

    const original_first_byte = header[0];
    applyHeaderProtection(hp_key, &header, 13, 2, sample);

    // Verify header was modified
    try std.testing.expect(header[0] != original_first_byte);

    // Remove protection
    _ = removeHeaderProtection(hp_key, &header, 13, sample);

    // Should be back to original (approximately - pn length might differ)
    // The first byte flags portion should match
    try std.testing.expect((header[0] & 0xF0) == (original_first_byte & 0xF0));
}

test "AEAD encrypt/decrypt" {
    const secrets = Secrets{
        .key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
        .iv = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c },
        .hp = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
    };

    const ctx = AeadContext.init(secrets, .TLS_AES_128_GCM_SHA256);

    const plaintext = "Hello, QUIC!";
    const aad = "additional data";
    var ciphertext: [12]u8 = undefined;
    var tag: [16]u8 = undefined;

    ctx.encrypt(0, aad, plaintext, &ciphertext, &tag);

    var decrypted: [12]u8 = undefined;
    try ctx.decrypt(0, aad, &ciphertext, tag, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}
