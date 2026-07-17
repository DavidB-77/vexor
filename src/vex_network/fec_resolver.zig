//! Vexor FEC Resolver
//!
//! Reed-Solomon Forward Error Correction for shred recovery.
//! @prov:fec.resolver
//!
//! FEC sets allow recovery of missing shreds using coding (parity) shreds.
//! Solana uses Reed-Solomon erasure coding in GF(2^8).

const std = @import("std");
const core = @import("core");
const gf_simd = @import("gf_simd.zig");
const bmtree = @import("bmtree.zig");
const dupshred = @import("duplicate_shred.zig");

/// @prov:fec.limits — maximum data shreds per FEC set
pub const MAX_DATA_SHREDS: usize = 67;

/// @prov:fec.limits — maximum parity/coding shreds per FEC set
pub const MAX_PARITY_SHREDS: usize = 67;

/// Total maximum shreds in an FEC set
pub const MAX_SHREDS_PER_FEC_SET: usize = MAX_DATA_SHREDS + MAX_PARITY_SHREDS;

/// Standard shred size
pub const SHRED_SIZE: usize = 1228;

/// Signature size in bytes (Ed25519)
pub const SIGNATURE_SIZE: usize = 64;

/// Chained merkle root size (SIMD-0340 chained_merkle_root, FD_SHRED_MERKLE_ROOT_SZ).
pub const MERKLE_ROOT_SIZE: usize = 32;

/// Retransmitter signature size (resigned variants, FD_ED25519_SIG_SZ = the 64-byte
/// retransmitter sig at the shred tail of 0x70/0xB0 variants).
pub const RETRANSMITTER_SIG_SIZE: usize = 64;

/// Data shred header size (common header 83 + data header 5)
pub const DATA_HEADER_SIZE: usize = 88;

/// Code shred header size (common header 83 + code header 6)
pub const CODE_HEADER_SIZE: usize = 89;

/// Solana data-shred on-wire size (signature + header + payload + merkle proof).
/// @prov:fec.wire-sizes — data shred payload is 1203 bytes.
///
/// FIX #56 (2026-05-27): recovered data shreds MUST be allocated at this size.
/// `FecSet.shred_sz` is a single field overwritten by every `addDataShred`/
/// `addParityShred` call; when parity (1228B) is added last, shred_sz=1228 and
/// data-shred recovery produces oversize buffers with zero-padded tails. The
/// 25 trailing zeros plus the never-reconstructed 120-byte proof region break
/// `Shred.chainedMerkleRoot()` payload-end-relative offset computation,
/// returning a spurious value and triggering false SIMD-0340 orphan kills.
/// See memory `project-fix56-fec-recovery-shred-size-bug-2026-05-27`.
pub const DATA_SHRED_WIRE_SIZE: usize = 1203;

/// Solana coding-shred on-wire size.
/// @prov:fec.wire-sizes — coding shred payload is 1228 bytes.
/// Equal to `SHRED_SIZE` above; named explicitly for symmetry with
/// `DATA_SHRED_WIRE_SIZE` so call-sites read clearly.
pub const CODE_SHRED_WIRE_SIZE: usize = 1228;

/// Merkle proof entry size (truncated hash)
pub const MERKLE_PROOF_ENTRY_SIZE: usize = 20;

/// Parse variant byte to extract shred type and proof_size
/// Per Solana spec:
/// - Legacy code: 0x5A (high=0x5, low=0xA)
/// - Legacy data: 0xA5 (high=0xA, low=0x5)
/// - Merkle code: high nibble 0x4, 0x6, or 0x7; low nibble = proof_size
/// - Merkle data: high nibble 0x8, 0x9, 0xA (if not 0xA5), 0xB; low nibble = proof_size
pub fn parseVariantByte(variant: u8) struct { is_data: bool, is_merkle: bool, proof_size: u8 } {
    const high_nibble = variant & 0xF0;
    const low_nibble = variant & 0x0F;

    // Check for Alpenglow V3: Variant 0x58 - special case
    // Proof size is 0, is_chained = true (based on 0x50 prefix)
    if (variant == 0x58) {
        return .{ .is_data = false, .is_merkle = true, .proof_size = 0 };
    }

    // Check for legacy variants first (exact match)
    if (variant == 0x5A) {
        return .{ .is_data = false, .is_merkle = false, .proof_size = 0 }; // Legacy code
    }
    if (variant == 0xA5) {
        return .{ .is_data = true, .is_merkle = false, .proof_size = 0 }; // Legacy data
    }

    // Merkle variants: high nibble determines type
    return switch (high_nibble) {
        // Merkle code variants: 0x4X, 0x6X, 0x7X
        0x40 => .{ .is_data = false, .is_merkle = true, .proof_size = low_nibble },
        0x60 => .{ .is_data = false, .is_merkle = true, .proof_size = low_nibble }, // chained
        0x70 => .{ .is_data = false, .is_merkle = true, .proof_size = low_nibble }, // chained+resigned
        // Merkle data variants: 0x8X, 0x9X, 0xAX, 0xBX
        0x80 => .{ .is_data = true, .is_merkle = true, .proof_size = low_nibble },
        0x90 => .{ .is_data = true, .is_merkle = true, .proof_size = low_nibble }, // chained
        0xA0 => .{ .is_data = true, .is_merkle = true, .proof_size = low_nibble }, // (but 0xA5 already handled)
        0xB0 => .{ .is_data = true, .is_merkle = true, .proof_size = low_nibble }, // chained+resigned
        else => .{ .is_data = false, .is_merkle = false, .proof_size = 0 },
    };
}

/// Is this a CHAINED merkle shred variant (SIMD-0340 chained_merkle_root present)?
/// Chained code: 0x60 (chained), 0x70 (chained+resigned). Chained data: 0x90
/// (chained), 0xB0 (chained+resigned). Plus 0x58 (Alpenglow V3, chained). The
/// plain merkle variants 0x40 (code) / 0x80 (data) are NOT chained.
///
/// WHY THIS MATTERS (2026-06-14, ticket #61 interim): our RS recovery does NOT
/// reconstruct the merkle proof or write the chained_merkle_root region of a
/// recovered data shred (it leaves the proof @memset(0) and lets the wrong-bounded
/// RS columns overwrite the chained_root region — see fec_resolver recovery diff vs
/// Agave merkle.rs:798-865). A recovered CHAINED shred therefore yields a garbage
/// merkleRoot32()/chainedMerkleRoot() → poisons the SIMD-0340 block_id chain check →
/// FALSE intra-slot violation → false dead slot → 136-slot cascade wedge (observed
/// live @415266588). Until the full #61 port lands (boundary fix + tree rebuild +
/// verify + make_merkle_proof), we SKIP recovery for chained sets and let repair
/// fetch the genuinely-missing shreds (WindowIndex). Non-chained recovery is
/// unaffected. This is Agave-faithful in effect: Agave rejects a recovery whose
/// rebuilt root != the signed root (InvalidMerkleRoot, merkle.rs:836) and likewise
/// falls back to repair.
pub fn isChainedVariant(variant: u8) bool {
    if (variant == 0x58) return true; // Alpenglow V3 chained
    return switch (variant & 0xF0) {
        0x60, 0x70, 0x90, 0xB0 => true,
        else => false,
    };
}

/// Is this a RESIGNED merkle shred variant (carries a 64-byte retransmitter
/// signature at the very tail of the payload, AFTER the proof)? Resigned is a
/// strict subset of chained: code resigned = 0x70, data resigned = 0xB0. The
/// plain-chained variants 0x60 (code) / 0x90 (data) and Alpenglow 0x58 are NOT
/// resigned. @prov:fec.resigned-variant
pub fn isResignedVariant(variant: u8) bool {
    return switch (variant & 0xF0) {
        0x70, 0xB0 => true,
        else => false,
    };
}

/// chained-skip diagnostic escape hatch (cached). #61 FULL (2026-06-14): the
/// default is now OFF — chained-merkle RS recovery RUNS (with the root-equality
/// self-gate). Set VEX_FEC_CHAINED_SKIP=1 to FORCE the old skip behaviour (e.g.
/// for the chain-tracker ordering diagnostic, where recovery would change FEC
/// arrival timing and confound the trace). Any value other than "1" leaves
/// recovery enabled.
var chained_skip_cached: ?bool = null;
pub fn chainedSkipEnabled() bool {
    if (chained_skip_cached) |v| return v;
    const on = if (std.posix.getenv("VEX_FEC_CHAINED_SKIP")) |s| std.mem.eql(u8, s, "1") else false;
    chained_skip_cached = on;
    return on;
}

/// Calculate the erasure shard size for a shred
/// For Merkle shreds, this EXCLUDES the merkle proof at the end
fn calculateErasureShardSize(shred: []const u8, is_data: bool) usize {
    if (shred.len <= 64) return 0;

    const variant = shred[64];
    const parsed = parseVariantByte(variant);

    // Calculate merkle proof size (only for Merkle shreds)
    const merkle_proof_size: usize = if (parsed.is_merkle)
        @as(usize, parsed.proof_size) * MERKLE_PROOF_ENTRY_SIZE
    else
        0;

    // The Reed-Solomon-protected region (= the "erasure shard") is the portion
    // of the payload the RS codec actually encodes. It EXCLUDES, in addition to
    // the merkle proof, the chained_merkle_root (32 B, chained variants) and the
    // resigned retransmitter signature (64 B, resigned variants) — both of which
    // are written AFTER RS encoding and live outside the coded region.
    //
    // @prov:fec.erasure-shard-size — subtracts
    //   leading_offset(sig 64 / code-header 89) + MERKLE_NODE_SZ*proof_depth
    //   + MERKLE_ROOT_SZ*is_chained + SIGNATURE_SZ*is_resigned.
    // VERIFIED against Vexor's OWN encoder (shred_encoder.zig): chained
    // non-resigned data shred 1203 - 64(sig) - 120(proof) - 32(chained_root) =
    // 987 == encoder `rs_sz` (the RS shard it actually encodes,
    // shred_encoder.zig:90,136). There is NO separate "signed merkle root"
    // payload term — the signed root is DERIVED (the merkle tree's root), not
    // stored in the shred, so it is NOT subtracted (would mis-size by 32 B and
    // make every chained set fail the rebuilt-root gate). Non-chained,
    // non-resigned merkle sets keep the old size (1203-64-120=1019) byte-for-byte
    // because both conditional terms are zero.
    const is_chained: usize = if (parsed.is_merkle and isChainedVariant(variant)) MERKLE_ROOT_SIZE else 0;
    const is_resigned: usize = if (parsed.is_merkle and isResignedVariant(variant)) RETRANSMITTER_SIG_SIZE else 0;

    // Erasure shard starts at different offsets for data vs code
    const start_offset: usize = if (is_data) SIGNATURE_SIZE else CODE_HEADER_SIZE;

    const trailer = merkle_proof_size + is_chained + is_resigned;

    // Erasure shard ends before the proof / chained_root / resigned-sig trailer
    if (shred.len <= start_offset + trailer) return 0;

    return shred.len - start_offset - trailer;
}

/// GF(2^8) Galois Field operations for Reed-Solomon
/// @prov:fec.galois-field
pub const GaloisField = struct {
    /// GF(2^8) multiplication using log/exp tables
    /// The field uses polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
    const PRIMITIVE_POLY: u16 = 0x11D;

    /// Logarithm table (256 entries)
    log_table: [256]u8,

    /// Exponent/antilog table (512 entries for wraparound)
    exp_table: [512]u8,

    pub fn init() GaloisField {
        var gf = GaloisField{
            .log_table = undefined,
            .exp_table = undefined,
        };

        // Build exp table: exp[i] = alpha^i where alpha is primitive element (2)
        var x: u16 = 1;
        for (0..255) |i| {
            gf.exp_table[i] = @truncate(x);
            gf.exp_table[i + 255] = @truncate(x); // Duplicate for easy wraparound

            // Multiply by alpha (2) in GF(2^8)
            x <<= 1;
            if (x & 0x100 != 0) {
                x ^= PRIMITIVE_POLY;
            }
        }
        gf.exp_table[510] = gf.exp_table[0];
        gf.exp_table[511] = gf.exp_table[1];

        // Build log table: log[exp[i]] = i
        gf.log_table[0] = 0; // log(0) is undefined, use 0
        for (0..255) |i| {
            gf.log_table[gf.exp_table[i]] = @truncate(i);
        }

        return gf;
    }

    /// Multiply two elements in GF(2^8)
    pub fn mul(self: *const GaloisField, a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        const log_a = self.log_table[a];
        const log_b = self.log_table[b];
        return self.exp_table[@as(u16, log_a) + @as(u16, log_b)];
    }

    /// Divide in GF(2^8): a / b
    pub fn div(self: *const GaloisField, a: u8, b: u8) u8 {
        if (a == 0) return 0;
        if (b == 0) return 0; // Division by zero
        const log_a = self.log_table[a];
        const log_b = self.log_table[b];
        // Handle wraparound: (log_a - log_b) mod 255
        const diff = @mod(@as(i16, log_a) - @as(i16, log_b) + 255, @as(i16, 255));
        return self.exp_table[@intCast(diff)];
    }

    /// Add in GF(2^8) - just XOR
    pub fn add(_: *const GaloisField, a: u8, b: u8) u8 {
        return a ^ b;
    }

    /// Inverse in GF(2^8)
    pub fn inv(self: *const GaloisField, a: u8) u8 {
        if (a == 0) return 0;
        return self.exp_table[255 - @as(u16, self.log_table[a])];
    }
};

/// FEC Set - tracks shreds for one FEC set
/// @prov:fec.set
pub const FecSet = struct {
    allocator: std.mem.Allocator,

    /// Slot this FEC set belongs to
    slot: core.Slot,

    /// FEC set index within the slot
    fec_set_idx: u32,

    /// Expected number of data shreds (from first parity shred header)
    data_shred_cnt: u16,

    /// Expected number of parity shreds
    parity_shred_cnt: u16,

    /// Received data shreds (indexed by position in FEC set, not global index)
    data_shreds: [MAX_DATA_SHREDS]?[]u8,

    /// Received parity shreds
    parity_shreds: [MAX_PARITY_SHREDS]?[]u8,

    /// Which data shreds we have
    data_received: std.StaticBitSet(MAX_DATA_SHREDS),

    /// Which parity shreds we have
    parity_received: std.StaticBitSet(MAX_PARITY_SHREDS),

    /// Count of received data shreds
    data_received_cnt: u16,

    /// Count of received parity shreds
    parity_received_cnt: u16,

    /// Whether this FEC set is complete (all data recovered)
    is_complete: bool,

    /// Shred size (all shreds in set must be same size)
    shred_sz: usize,

    /// Last time recovery was attempted and failed (for backoff)
    last_failed_recovery_time: i64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, slot: core.Slot, fec_set_idx: u32) Self {
        return Self{
            .allocator = allocator,
            .slot = slot,
            .fec_set_idx = fec_set_idx,
            .data_shred_cnt = 0,
            .parity_shred_cnt = 0,
            .data_shreds = [_]?[]u8{null} ** MAX_DATA_SHREDS,
            .parity_shreds = [_]?[]u8{null} ** MAX_PARITY_SHREDS,
            .data_received = std.StaticBitSet(MAX_DATA_SHREDS).initEmpty(),
            .parity_received = std.StaticBitSet(MAX_PARITY_SHREDS).initEmpty(),
            .data_received_cnt = 0,
            .parity_received_cnt = 0,
            .is_complete = false,
            .shred_sz = SHRED_SIZE,
            .last_failed_recovery_time = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (&self.data_shreds) |*shred| {
            if (shred.*) |s| {
                self.allocator.free(s);
                shred.* = null;
            }
        }
        for (&self.parity_shreds) |*shred| {
            if (shred.*) |s| {
                self.allocator.free(s);
                shred.* = null;
            }
        }
    }

    /// Add a data shred to this FEC set
    /// pos is the position within the FEC set (0-based)
    pub fn addDataShred(self: *Self, pos: u16, data: []const u8) !void {
        if (pos >= MAX_DATA_SHREDS) return error.InvalidPosition;
        if (self.data_received.isSet(pos)) return; // Already have it

        // Copy the shred data
        const copy = try self.allocator.alloc(u8, data.len);
        @memcpy(copy, data);

        self.data_shreds[pos] = copy;
        self.data_received.set(pos);
        self.data_received_cnt += 1;
        self.shred_sz = data.len;
    }

    /// Add a parity/coding shred to this FEC set
    pub fn addParityShred(self: *Self, pos: u16, data: []const u8, num_data: u16, num_parity: u16) !void {
        if (pos >= MAX_PARITY_SHREDS) return error.InvalidPosition;
        if (self.parity_received.isSet(pos)) return; // Already have it

        // Update expected counts from the parity shred header
        // FIX: Validate counts to prevent out-of-bounds access later
        if (self.data_shred_cnt == 0) {
            self.data_shred_cnt = @min(num_data, MAX_DATA_SHREDS);
            self.parity_shred_cnt = @min(num_parity, MAX_PARITY_SHREDS);
        }

        // Copy the shred data
        const copy = try self.allocator.alloc(u8, data.len);
        @memcpy(copy, data);

        self.parity_shreds[pos] = copy;
        self.parity_received.set(pos);
        self.parity_received_cnt += 1;
        self.shred_sz = data.len;
    }

    /// True if this FEC set's shreds are CHAINED merkle (SIMD-0340). Determined
    /// from the variant byte (offset 64) of the first available data or parity
    /// shred. Used to gate RS recovery off for chained sets until ticket #61
    /// (see isChainedVariant). Returns false if no shred is available yet.
    pub fn isChained(self: *const FecSet) bool {
        for (self.data_shreds) |maybe| {
            if (maybe) |s| if (s.len > 64) return isChainedVariant(s[64]);
        }
        for (self.parity_shreds) |maybe| {
            if (maybe) |s| if (s.len > 64) return isChainedVariant(s[64]);
        }
        return false;
    }

    /// Check if we have enough shreds to attempt recovery
    pub fn canRecover(self: *const FecSet) bool {
        if (self.is_complete) return false;
        if (self.data_shred_cnt == 0) return false;

        // Backoff check: Don't retry immediately if we just failed
        // This prevents CPU spinning on unrecoverable sets (e.g., mismatching shred data)
        const now = std.time.milliTimestamp();
        if (now < self.last_failed_recovery_time + 1000) {
            return false;
        }

        const total_needed = self.data_shred_cnt;
        const total_have = self.data_received_cnt + self.parity_received_cnt;

        return total_have >= total_needed;
    }

    /// Check if already complete (have all data shreds)
    pub fn isComplete(self: *const Self) bool {
        if (self.data_shred_cnt == 0) return false;
        return self.data_received_cnt >= self.data_shred_cnt;
    }

    /// Get missing data shred indices
    pub fn getMissingDataIndices(self: *const Self, out: []u16) usize {
        var count: usize = 0;
        // FIX: Clamp data_shred_cnt to prevent out-of-bounds access
        const max_idx = @min(self.data_shred_cnt, MAX_DATA_SHREDS);
        for (0..max_idx) |i| {
            if (!self.data_received.isSet(i)) {
                if (count < out.len) {
                    out[count] = @intCast(i);
                    count += 1;
                }
            }
        }
        return count;
    }
};

/// FEC Resolver - manages multiple FEC sets and performs recovery
/// @prov:fec.resolver
pub const FecResolver = struct {
    allocator: std.mem.Allocator,

    /// Galois field for Reed-Solomon operations
    gf: GaloisField,

    /// SIMD-accelerated GF(2^8) engine (GFNI/AVX2/scalar)
    simd: gf_simd.GfSimd,

    /// Enable SIMD acceleration for FEC (gated by --enable-simd-fec)
    enable_simd_fec: bool,

    /// Active FEC sets by (slot, fec_set_idx) key
    active_sets: std.AutoHashMap(FecSetKey, *FecSet),

    /// Maximum concurrent FEC sets to track
    max_depth: usize,

    /// Shred version filter
    expected_shred_version: u16,

    /// Statistics
    stats: Stats,

    /// Disable RS recovery (Data-Only mode)
    /// When true, FEC sets are tracked but recovery is never attempted.
    /// This avoids the SIGSEGV crash from the RS implementation while
    /// still allowing complete slots (where all data shreds arrive naturally).
    disable_recovery: bool,

    /// Serializes ALL access to `active_sets` and the `*FecSet` it owns.
    /// REQUIRED because addShred is called from TWO threads concurrently:
    ///   1. the AF_XDP recv thread directly (tvu.zig:1030/1065 zero-copy path), and
    ///   2. verify-worker threads via ShredAssembler.insertBatch (under the
    ///      assembler mutex, shred.zig:1264).
    /// Without it, the recv thread's getOrCreateSet eviction (destroy of a
    /// FecSet) raced a worker mid-iteration of `set.data_shreds` → use-after-free
    /// → SIGSEGV in addShred at fec_resolver.zig:298 (surfaced as a "jemalloc"
    /// crash at variable zc_pushed points during AF_XDP catch-up, 2026-06-14).
    /// The old "no lock needed for fec_resolver" comment at the recv call site
    /// was the bug. Lock ordering: recv thread takes ONLY this mutex; workers
    /// take assembler.mutex then this — never inverted, so no deadlock.
    fec_mutex: std.Thread.Mutex = .{},

    /// DuplicateShred (CRDS type 9) Tier-1 detection — equivocation conflicts
    /// captured under `fec_mutex` when a NEW raw payload collides with an
    /// already-stored payload at the SAME (slot, index, shred_type) position but
    /// DIFFERS after the retransmitter signature is stripped. ALWAYS compiled
    /// (bank-hash-neutral observation); the OUTBOUND gossip PUSH that drains this
    /// is the only flag+env-gated behaviour (see gossip.zig). Initialised lazily
    /// because FecResolver structs are built without an allocator-bound queue at
    /// some call sites; `recordConflict` no-ops if the queue is absent.
    conflict_queue: ?dupshred.ConflictQueue = null,
    duplicates_detected: u64 = 0,

    const Self = @This();

    pub const FecSetKey = u128;
    pub inline fn makeKey(slot: core.Slot, fec_set_idx: u32) FecSetKey {
        return (@as(u128, slot) << 64) | @as(u128, fec_set_idx);
    }

    pub const Stats = struct {
        sets_started: u64 = 0,
        sets_completed: u64 = 0,
        shreds_received: u64 = 0,
        shreds_recovered: u64 = 0,
        recovery_failures: u64 = 0,
        recovery_skipped: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, max_depth: usize, shred_version: u16) Self {
        return initWithConfig(allocator, max_depth, shred_version, false);
    }

    /// Create with SIMD FEC enabled
    pub fn initWithSimd(allocator: std.mem.Allocator, max_depth: usize, shred_version: u16) Self {
        return initWithConfig(allocator, max_depth, shred_version, true);
    }

    fn initWithConfig(allocator: std.mem.Allocator, max_depth: usize, shred_version: u16, simd_enabled: bool) Self {
        const simd_engine = gf_simd.GfSimd.init();
        const runtime_tier = gf_simd.detectTierRuntime();
        if (simd_enabled) {
            std.log.info("[FEC] SIMD engine: comptime={s}, runtime={s}", .{
                gf_simd.active_tier.name(), runtime_tier.name(),
            });
        }
        return Self{
            .allocator = allocator,
            .gf = GaloisField.init(),
            .simd = simd_engine,
            .enable_simd_fec = simd_enabled,
            .active_sets = std.AutoHashMap(FecSetKey, *FecSet).init(allocator),
            .max_depth = max_depth,
            .expected_shred_version = shred_version,
            .stats = Stats{},
            .disable_recovery = false,
            .conflict_queue = dupshred.ConflictQueue.init(allocator),
        };
    }

    /// Create with recovery disabled (Data-Only mode for stability)
    pub fn initDataOnly(allocator: std.mem.Allocator, max_depth: usize, shred_version: u16) Self {
        var resolver = init(allocator, max_depth, shred_version);
        resolver.disable_recovery = true;
        return resolver;
    }

    pub fn deinit(self: *Self) void {
        var it = self.active_sets.valueIterator();
        while (it.next()) |set| {
            set.*.deinit();
            self.allocator.destroy(set.*);
        }
        self.active_sets.deinit();
        if (self.conflict_queue) |*q| q.deinit();
    }

    /// Drain one detected equivocation conflict (oldest first), or null when
    /// none pending. Caller takes ownership of the returned Conflict's payload
    /// slices and MUST call `Conflict.deinit(allocator)`. Thread-safe (takes
    /// fec_mutex). Called by the gossip side ONLY when the DuplicateShred push is
    /// flag+env enabled — detection itself always runs.
    pub fn popConflict(self: *Self) ?dupshred.Conflict {
        self.fec_mutex.lock();
        defer self.fec_mutex.unlock();
        if (self.conflict_queue) |*q| return q.pop();
        return null;
    }

    /// Tier-1 equivocation check + capture. Compares a NEW raw payload against
    /// the STORED raw payload occupying the same FEC-set position (which already
    /// guarantees same slot/index/shred_type). If they differ after stripping
    /// the trailing retransmitter signature (resigned variants only), records an
    /// owned-copy conflict on the queue. MUST be called with `fec_mutex` HELD.
    /// Both payloads are already leader-signature-verified by the caller.
    fn recordConflictLocked(self: *Self, slot: core.Slot, shred_index: u32, stored: []const u8, incoming: []const u8) void {
        // Need at least the variant byte (offset 64) to know `resigned`.
        if (stored.len <= 64 or incoming.len <= 64) return;
        const resigned_stored = isResignedVariant(stored[64]);
        const resigned_incoming = isResignedVariant(incoming[64]);
        if (!dupshred.isConflict(stored, resigned_stored, incoming, resigned_incoming)) return;
        if (self.conflict_queue) |*q| {
            if (q.push(@as(u64, slot), shred_index, stored, incoming)) {
                self.duplicates_detected += 1;
                std.log.warn(
                    "[DUP-SHRED] equivocation detected slot={d} index={d} (stored {d}B vs new {d}B)",
                    .{ slot, shred_index, stored.len, incoming.len },
                );
            }
        }
    }

    /// Get or create FEC set for a shred
    fn getOrCreateSet(self: *Self, slot: core.Slot, fec_set_idx: u32) !*FecSet {
        const key = makeKey(slot, fec_set_idx);

        if (self.active_sets.get(key)) |existing| {
            return existing;
        }

        // Evict oldest if at capacity
        if (self.active_sets.count() >= self.max_depth) {
            // Simple eviction: remove first entry
            var iter = self.active_sets.iterator();
            if (iter.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.destroy(entry.value_ptr.*);
                _ = self.active_sets.remove(entry.key_ptr.*);
            }
        }

        // Create new set
        const new_set = try self.allocator.create(FecSet);
        new_set.* = FecSet.init(self.allocator, slot, fec_set_idx);
        try self.active_sets.put(key, new_set);
        self.stats.sets_started += 1;

        return new_set;
    }

    /// Result of adding a shred
    pub const AddResult = enum {
        /// Shred added, waiting for more
        pending,
        /// FEC set complete, all data shreds available
        complete,
        /// Shred was duplicate
        duplicate,
        /// Shred version mismatch
        version_mismatch,
        /// Error during processing
        err,
    };

    /// Add a shred and attempt recovery if possible
    /// Returns complete if the FEC set now has all data shreds
    /// @prov:fec.add-shred
    pub fn addShred(
        self: *Self,
        slot: core.Slot,
        shred_index: u32,
        fec_set_idx: u32,
        is_data: bool,
        shred_data: []const u8,
        shred_version: u16,
        // For parity shreds only:
        num_data: u16,
        num_parity: u16,
        parity_position: u16,
    ) !FecResolver.AddResult {
        // THREAD SAFETY (2026-06-14): serialize the whole add — getOrCreateSet
        // (which can evict+destroy a FecSet) and the per-set mutation below race
        // the verify-worker insertBatch path otherwise. See fec_mutex doc.
        self.fec_mutex.lock();
        defer self.fec_mutex.unlock();

        // DEFENSIVE: Validate shred_data length (prevents buffer overruns)
        // Firedancer uses SHRED_SIZE=1228, we allow some flexibility
        if (shred_data.len < 88 or shred_data.len > 2048) {
            std.log.warn("[FEC] Rejecting shred with invalid size {d}", .{shred_data.len});
            return .err;
        }

        // DEFENSIVE: Validate FEC set parameters (Firedancer MAX = 67)
        if (num_data > MAX_DATA_SHREDS or num_parity > MAX_PARITY_SHREDS) {
            std.log.warn("[FEC] Rejecting shred with invalid FEC params: data={d}, parity={d}", .{ num_data, num_parity });
            return .err;
        }

        // DEFENSIVE: Validate parity position
        if (!is_data and parity_position >= MAX_PARITY_SHREDS) {
            std.log.warn("[FEC] Rejecting parity shred with invalid position {d}", .{parity_position});
            return .err;
        }

        // Check shred version
        if (shred_version != self.expected_shred_version and self.expected_shred_version != 0) {
            return .version_mismatch;
        }

        self.stats.shreds_received += 1;

        const set = self.getOrCreateSet(slot, fec_set_idx) catch |err| {
            std.log.err("[FEC] Failed to getOrCreateSet for slot {d} fec {d}: {}", .{ slot, fec_set_idx, err });
            return .err;
        };

        if (is_data) {
            // Data shred index MUST be >= fec_set_idx for Merkle V2
            if (shred_index < fec_set_idx) return .err;
            const diff = shred_index - fec_set_idx;
            if (diff >= MAX_DATA_SHREDS) return .err;
            const pos: u16 = @intCast(diff);
            // DUP-SHRED Tier-1 detection: if this position is already filled, the
            // STORED payload shares (slot, index, shred_type) with the incoming
            // one. addDataShred silently returns on a re-insert, so we compare
            // here BEFORE it. A differing body (after stripping the retransmitter
            // sig) is leader equivocation. (fec_mutex is held for the whole add.)
            if (set.data_received.isSet(pos)) {
                if (set.data_shreds[pos]) |stored| {
                    self.recordConflictLocked(slot, shred_index, stored, shred_data);
                }
            }
            set.addDataShred(pos, shred_data) catch return .duplicate;
        } else {
            // DUP-SHRED Tier-1 detection for coding/parity shreds (same logic).
            if (parity_position < MAX_PARITY_SHREDS and set.parity_received.isSet(parity_position)) {
                if (set.parity_shreds[parity_position]) |stored| {
                    self.recordConflictLocked(slot, shred_index, stored, shred_data);
                }
            }
            set.addParityShred(parity_position, shred_data, num_data, num_parity) catch return .duplicate;

            // Log parity shred receipt (helpful for debugging)
            if (set.parity_received_cnt == 1) {
                // std.log.debug("[FEC] Slot {d} FEC set {d}: first parity, expect {d} data + {d} parity\n", .{
                //    slot, fec_set_idx, num_data, num_parity,
                // });
            }
        }

        // Check if already complete
        if (set.isComplete()) {
            set.is_complete = true;
            self.stats.sets_completed += 1;
            // std.log.debug("[FEC] Slot {d} FEC set {d} COMPLETE (all data received)\n", .{ slot, fec_set_idx });
            return .complete;
        }

        // Try recovery if we have enough shreds
        if (set.canRecover()) {
            if (self.disable_recovery) {
                // Data-Only mode: skip RS recovery to avoid SIGSEGV
                self.stats.recovery_skipped += 1;
                return .pending;
            }
            // #61 FULL (2026-06-14): chained-merkle RS recovery is NOW supported.
            // recoverWithSigMethod reconstructs missing data AND parity, re-stamps
            // the FEC-set signature + chained_merkle_root into each recovered shred,
            // rebuilds the 64-leaf merkle tree, and REJECTS the whole set unless the
            // rebuilt root == the surviving leader-signed root (replaces per-shred
            // ed25519 verify; @prov:fec.chained-merkle-recovery).
            // A failed gate inserts nothing and leaves the set .pending so repair
            // fills genuine shreds — same fallback as the old skip, but now we
            // recover the common case from coding shreds instead of repairing 1-by-1.
            // The VEX_FEC_CHAINED_SKIP=1 escape hatch is retained for diagnostics.
            if (set.isChained() and chainedSkipEnabled()) {
                self.stats.recovery_skipped += 1;
                const n = self.stats.recovery_skipped;
                if (n <= 3 or @mod(n, 500) == 0) {
                    std.log.warn("[FEC-CHAINED-SKIP] slot={d} fec_set_idx={d}: skipping RS recovery for chained set (VEX_FEC_CHAINED_SKIP=1 forced) — skipped_total={d}", .{ slot, fec_set_idx, n });
                }
                return .pending;
            }
            // std.log.debug("[FEC] Slot {d} FEC set {d}: attempting recovery (have {d} data + {d} parity, need {d})\n", .{
            //     slot, fec_set_idx, set.data_received_cnt, set.parity_received_cnt, set.data_shred_cnt,
            // });
            const recovered = self.tryRecover(set);
            if (recovered) {
                set.is_complete = true;
                self.stats.sets_completed += 1;
                // std.log.debug("[FEC] Slot {d} FEC set {d} RECOVERED!\n", .{ slot, fec_set_idx });
                return .complete;
            } else {
                // std.log.debug("[FEC] Slot {d} FEC set {d}: recovery FAILED\n", .{ slot, fec_set_idx });
            }
        }

        return .pending;
    }

    /// Attempt Reed-Solomon recovery on an FEC set
    /// @prov:fec.reed-solomon-recover
    ///
    /// Algorithm:
    /// 1. Build Vandermonde matrix V where V[i,j] = i^j for all shards
    /// 2. Pick rows corresponding to available shards to form submatrix
    /// 3. Invert the submatrix using Gaussian elimination
    /// 4. Multiply inverted matrix by available shard data to get missing data
    fn tryRecover(self: *Self, set: *FecSet) bool {
        if (set.data_shred_cnt == 0) return false;

        // Count missing data shreds
        var missing: [MAX_DATA_SHREDS]u16 = undefined;
        const missing_cnt = set.getMissingDataIndices(&missing);

        if (missing_cnt == 0) {
            // Already complete!
            return true;
        }

        // Need at least missing_cnt parity shreds to recover
        if (set.parity_received_cnt < missing_cnt) {
            return false;
        }

        // Perform Reed-Solomon recovery using Sig's matrix approach
        const recovered = self.recoverWithSigMethod(set, missing[0..missing_cnt]) catch {
            self.stats.recovery_failures += 1;
            set.last_failed_recovery_time = std.time.milliTimestamp();
            return false;
        };

        if (recovered) {
            self.stats.shreds_recovered += @intCast(missing_cnt);
        } else {
            set.last_failed_recovery_time = std.time.milliTimestamp();
        }

        return recovered;
    }

    /// Reed-Solomon recovery using the encoding matrix approach
    /// @prov:fec.reed-solomon-recover
    ///
    /// Key insight: the encoding matrix M = V * inv(top(V)) has the property that
    /// the top n rows are identity (data shards unchanged) and bottom m rows compute parity.
    /// For decoding, we pick rows from M, not raw Vandermonde.
    ///
    /// SAFETY: Uses ArenaAllocator for all temporary matrices (~50KB total)
    /// to avoid blowing the thread stack during repair bursts.
    fn recoverWithSigMethod(self: *Self, set: *FecSet, missing_indices: []const u16) !bool {
        const n: usize = set.data_shred_cnt;
        const m: usize = set.parity_shred_cnt;
        const k = missing_indices.len;
        const shred_sz = set.shred_sz;

        if (k == 0) return true;
        if (shred_sz == 0) return false;
        if (n == 0 or n > MAX_DATA_SHREDS) return false;
        if (m == 0 or m > MAX_PARITY_SHREDS) return false;
        if (n + m > MAX_SHREDS_PER_FEC_SET) return false;

        const total = n + m;
        const total_available = set.data_received_cnt + set.parity_received_cnt;
        if (total_available < n) return false;

        // ── Arena allocator for all temporary matrices ──────────────────
        // Freed in bulk when this function returns — no leak risk.
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const tmp = arena.allocator();

        // Determine erasure shard boundaries using proper Merkle-aware calculation
        var erasure_sz: usize = 0;
        var data_start: usize = SIGNATURE_SIZE;
        var proof_size: u8 = 0;
        var is_merkle = true;

        // Get erasure size from first available data shred
        for (0..n) |i| {
            if (set.data_shreds[i]) |shred| {
                erasure_sz = calculateErasureShardSize(shred, true);
                if (shred.len > 64) {
                    const variant = shred[64];
                    const parsed = parseVariantByte(variant);
                    is_merkle = parsed.is_merkle;
                    proof_size = parsed.proof_size;
                    data_start = if (is_merkle) SIGNATURE_SIZE else 0;
                }
                break;
            }
        }

        // If no data shred available, get from parity shred
        if (erasure_sz == 0) {
            for (0..m) |i| {
                if (set.parity_shreds[i]) |shred| {
                    erasure_sz = calculateErasureShardSize(shred, false);
                    if (shred.len > 64) {
                        const variant = shred[64];
                        const parsed = parseVariantByte(variant);
                        is_merkle = parsed.is_merkle;
                        proof_size = parsed.proof_size;
                    }
                    break;
                }
            }
        }

        // ── STRICT BOUNDS VALIDATION ────────────────────────────────────
        if (erasure_sz == 0) {
            std.log.err("[FEC] Could not determine erasure shard size", .{});
            return false;
        }
        const max_erasure_sz = if (shred_sz > SIGNATURE_SIZE) shred_sz - SIGNATURE_SIZE else 0;
        if (erasure_sz > max_erasure_sz) {
            std.log.err("[FEC] erasure_sz {d} exceeds max {d} (shred_sz={d}), likely corrupted variant", .{
                erasure_sz, max_erasure_sz, shred_sz,
            });
            return false;
        }
        if (data_start + erasure_sz > shred_sz) {
            std.log.err("[FEC] data_start({d}) + erasure_sz({d}) > shred_sz({d}), aborting recovery", .{
                data_start, erasure_sz, shred_sz,
            });
            return false;
        }

        const merkle_proof_sz: usize = if (is_merkle) @as(usize, proof_size) * MERKLE_PROOF_ENTRY_SIZE else 0;

        std.log.debug("[FEC] Erasure params: is_merkle={any}, proof_size={d}, merkle_proof_bytes={d}, erasure_sz={d}, data_start={d}", .{ is_merkle, proof_size, merkle_proof_sz, erasure_sz, data_start });

        // ── #61 CHAINED-MERKLE RECOVERY METADATA ────────────────────────
        // Capture the variant flags + the FEC-set-common chained_merkle_root +
        // the surviving SIGNED merkle root. After RS reconstruct we restamp the
        // signature + chained_root into each recovered shred's tail, rebuild the
        // 64-leaf merkle tree, and REJECT the whole set unless the rebuilt root
        // matches this signed root. @prov:fec.chained-merkle-recovery
        var set_is_chained = false;
        var set_is_resigned = false;
        if (is_merkle) {
            // Use the variant of a surviving shred (data first, else parity).
            var v: u8 = 0;
            var found_variant = false;
            for (0..n) |i| {
                if (set.data_shreds[i]) |s| {
                    if (s.len > 64) {
                        v = s[64];
                        found_variant = true;
                    }
                    break;
                }
            }
            if (!found_variant) {
                for (0..m) |i| {
                    if (set.parity_shreds[i]) |s| {
                        if (s.len > 64) {
                            v = s[64];
                            found_variant = true;
                        }
                        break;
                    }
                }
            }
            if (found_variant) {
                set_is_chained = isChainedVariant(v);
                set_is_resigned = isResignedVariant(v);
            }
        }

        // ── HEAP-ALLOCATED MATRICES (via arena) ─────────────────────────
        // Total: ~4 matrices of n×n + 2 matrices of total×n ≈ 4×67² + 2×134×67 ≈ ~36KB
        // All freed by arena.deinit() on return.
        const vandermonde = try tmp.alloc(u8, total * n);
        const top_inv = try tmp.alloc(u8, n * n);
        const augmented = try tmp.alloc(u8, n * 2 * n);
        const enc_matrix = try tmp.alloc(u8, total * n);
        const sub_matrix = try tmp.alloc(u8, n * n);
        const sub_aug = try tmp.alloc(u8, n * 2 * n);
        const decode_matrix = try tmp.alloc(u8, n * n);
        const available_rows = try tmp.alloc(usize, n);
        const available_shards = try tmp.alloc([]const u8, n);

        // Step 1: Build full Vandermonde matrix V (total x n)
        for (0..total) |row| {
            const x: u8 = @intCast(row);
            var x_pow: u8 = 1;
            for (0..n) |col| {
                vandermonde[row * n + col] = x_pow;
                if (x == 0) {
                    x_pow = 0;
                } else {
                    x_pow = self.gf.mul(x_pow, x);
                }
            }
        }

        // Step 2: Extract and invert top n x n submatrix
        for (0..n) |row| {
            for (0..n) |col| {
                augmented[row * (2 * n) + col] = vandermonde[row * n + col];
            }
            for (0..n) |col| {
                augmented[row * (2 * n) + n + col] = if (row == col) 1 else 0;
            }
        }

        // Gaussian elimination (top submatrix)
        for (0..n) |col| {
            var pivot_row = col;
            while (pivot_row < n and augmented[pivot_row * (2 * n) + col] == 0) pivot_row += 1;
            if (pivot_row >= n) return false;

            if (pivot_row != col) {
                for (0..(2 * n)) |c| {
                    const tmp_val = augmented[col * (2 * n) + c];
                    augmented[col * (2 * n) + c] = augmented[pivot_row * (2 * n) + c];
                    augmented[pivot_row * (2 * n) + c] = tmp_val;
                }
            }

            const pivot_val = augmented[col * (2 * n) + col];
            if (pivot_val != 1) {
                const inv_pivot = self.gf.inv(pivot_val);
                for (0..(2 * n)) |c| {
                    augmented[col * (2 * n) + c] = self.gf.mul(augmented[col * (2 * n) + c], inv_pivot);
                }
            }

            for (0..n) |row| {
                if (row != col) {
                    const factor = augmented[row * (2 * n) + col];
                    if (factor != 0) {
                        for (0..(2 * n)) |c| {
                            augmented[row * (2 * n) + c] = self.gf.add(augmented[row * (2 * n) + c], self.gf.mul(factor, augmented[col * (2 * n) + c]));
                        }
                    }
                }
            }
        }

        for (0..n) |row| {
            for (0..n) |col| {
                top_inv[row * n + col] = augmented[row * (2 * n) + n + col];
            }
        }

        // Step 3: Compute encoding matrix M = V * top_inv
        for (0..total) |row| {
            for (0..n) |col| {
                var sum: u8 = 0;
                for (0..n) |kk| {
                    sum = self.gf.add(sum, self.gf.mul(vandermonde[row * n + kk], top_inv[kk * n + col]));
                }
                enc_matrix[row * n + col] = sum;
            }
        }

        // Step 4: Collect available shards and their row indices
        // ── CRITICAL FIX: Uniform padding for ALL shards ──────────────────
        // The SIGSEGV that caused disable_recovery=true was here: data shards
        // were sliced to variable lengths (depending on merkle proof size per
        // individual shred), while parity shards were padded to a single
        // target_erasure_sz. When mulAccum(dst, src, coeff) asserts
        // dst.len == src.len, any mismatch is a crash.
        //
        // Fix: First pass — scan ALL available shreds to find the maximum
        // erasure portion length. Second pass — pad every shard to that
        // exact length. This guarantees uniform buffers for the SIMD engine.
        var available_count: usize = 0;

        // The RS shard ENDS before the proof AND the chained_root (32 B, chained)
        // AND the resigned retransmitter sig (64 B, resigned) — none of which are
        // RS-coded. Pre-#61 this used only merkle_proof_sz, which let chained sets
        // include the 32-byte chained_root in the RS region (wrong by 32 B). See
        // calculateErasureShardSize / FD reedsol_protected_sz (fd_fec_resolver.c:622).
        const rs_trailer: usize = merkle_proof_sz +
            (if (set_is_chained) MERKLE_ROOT_SIZE else 0) +
            (if (set_is_resigned) RETRANSMITTER_SIG_SIZE else 0);

        // ── First pass: determine uniform_erasure_sz across ALL shards ────
        var uniform_erasure_sz: usize = erasure_sz;

        for (0..n) |i| {
            if (set.data_shreds[i]) |shred| {
                const end_offset = if (shred.len > rs_trailer) shred.len - rs_trailer else shred.len;
                if (end_offset > data_start) {
                    const shard_len = end_offset - data_start;
                    uniform_erasure_sz = @max(uniform_erasure_sz, shard_len);
                }
            }
        }

        const code_start: usize = CODE_HEADER_SIZE;
        for (0..m) |i| {
            if (set.parity_shreds[i]) |shred| {
                const end_offset = if (shred.len > rs_trailer) shred.len - rs_trailer else shred.len;
                if (end_offset > code_start) {
                    const shard_len = end_offset - code_start;
                    uniform_erasure_sz = @max(uniform_erasure_sz, shard_len);
                }
            }
        }

        if (uniform_erasure_sz == 0) {
            std.log.err("[FEC] uniform_erasure_sz is 0, cannot recover", .{});
            return false;
        }

        // ── Second pass: collect shards, ALL padded to uniform_erasure_sz ─
        // Data shards
        for (0..n) |i| {
            if (available_count >= n) break;
            if (set.data_shreds[i]) |shred| {
                const end_offset = if (shred.len > rs_trailer) shred.len - rs_trailer else shred.len;
                if (end_offset > data_start) {
                    const raw = shred[data_start..end_offset];
                    // Pad to uniform size (arena-allocated — freed on return)
                    const padded = try tmp.alloc(u8, uniform_erasure_sz);
                    @memset(padded, 0);
                    const copy_len = @min(raw.len, uniform_erasure_sz);
                    @memcpy(padded[0..copy_len], raw[0..copy_len]);

                    available_rows[available_count] = i;
                    available_shards[available_count] = padded;
                    available_count += 1;
                }
            }
        }

        // Parity shards
        for (0..m) |i| {
            if (available_count >= n) break;
            if (set.parity_shreds[i]) |shred| {
                const end_offset = if (shred.len > rs_trailer) shred.len - rs_trailer else shred.len;
                if (end_offset > code_start) {
                    const raw = shred[code_start..end_offset];
                    // Pad to uniform size (same as data shards)
                    const padded = try tmp.alloc(u8, uniform_erasure_sz);
                    @memset(padded, 0);
                    const copy_len = @min(raw.len, uniform_erasure_sz);
                    @memcpy(padded[0..copy_len], raw[0..copy_len]);

                    available_rows[available_count] = n + i;
                    available_shards[available_count] = padded;
                    available_count += 1;
                }
            }
        }

        if (available_count < n) {
            std.log.debug("[FEC] Not enough available shards: have {d}, need {d}", .{ available_count, n });
            return false;
        }

        // Step 5: Build submatrix from enc_matrix rows and invert
        for (0..n) |row| {
            const enc_row = available_rows[row];
            for (0..n) |col| {
                sub_matrix[row * n + col] = enc_matrix[enc_row * n + col];
            }
        }

        // Invert sub_matrix (Gaussian elimination)
        for (0..n) |row| {
            for (0..n) |col| {
                sub_aug[row * (2 * n) + col] = sub_matrix[row * n + col];
            }
            for (0..n) |col| {
                sub_aug[row * (2 * n) + n + col] = if (row == col) 1 else 0;
            }
        }

        for (0..n) |col| {
            var pivot_row = col;
            while (pivot_row < n and sub_aug[pivot_row * (2 * n) + col] == 0) pivot_row += 1;
            if (pivot_row >= n) return false;

            if (pivot_row != col) {
                for (0..(2 * n)) |c| {
                    const tmp_val = sub_aug[col * (2 * n) + c];
                    sub_aug[col * (2 * n) + c] = sub_aug[pivot_row * (2 * n) + c];
                    sub_aug[pivot_row * (2 * n) + c] = tmp_val;
                }
            }

            const pivot_val = sub_aug[col * (2 * n) + col];
            if (pivot_val != 1) {
                const inv_pivot = self.gf.inv(pivot_val);
                for (0..(2 * n)) |c| {
                    sub_aug[col * (2 * n) + c] = self.gf.mul(sub_aug[col * (2 * n) + c], inv_pivot);
                }
            }

            for (0..n) |row| {
                if (row != col) {
                    const factor = sub_aug[row * (2 * n) + col];
                    if (factor != 0) {
                        for (0..(2 * n)) |c| {
                            sub_aug[row * (2 * n) + c] = self.gf.add(sub_aug[row * (2 * n) + c], self.gf.mul(factor, sub_aug[col * (2 * n) + c]));
                        }
                    }
                }
            }
        }

        for (0..n) |row| {
            for (0..n) |col| {
                decode_matrix[row * n + col] = sub_aug[row * (2 * n) + n + col];
            }
        }

        // ── GF dot-product reconstruct into a TEMP buffer ───────────────
        // INVERTED loop: per missing shred, accumulate decode_matrix[row]·shards
        // over the uniform RS region. SIMD path uses mulAccum (GFNI 64B / AVX2
        // 32B / scalar tail); scalar path is byte-by-byte. `decode_matrix` rows
        // are indexed by erasure-shard index: 0..n = data shards, n..n+m = parity
        // shards (enc_matrix already spans `total` rows, Step 3). This lets us
        // reconstruct BOTH missing data AND missing parity — both are needed to
        // build all 64 merkle leaves for the root-equality gate (FD :881-926 /
        // Agave reconstruct() fills every shard before make_merkle_tree).
        const reconstructRegion = struct {
            fn run(rself: *Self, dst: []u8, dmatrix: []const u8, row_idx: usize, nn: usize, shards: []const []const u8, usz: usize) void {
                if (rself.enable_simd_fec) {
                    for (0..nn) |j| {
                        const coeff = dmatrix[row_idx * nn + j];
                        rself.simd.mulAccum(dst, shards[j][0..usz], coeff);
                    }
                } else {
                    for (0..usz) |byte_idx| {
                        var val: u8 = 0;
                        for (0..nn) |j| {
                            const coeff = dmatrix[row_idx * nn + j];
                            val = rself.gf.add(val, rself.gf.mul(coeff, shards[j][byte_idx]));
                        }
                        dst[byte_idx] = val;
                    }
                }
            }
        }.run;

        // Need a decode row for every erasure-shard index (data 0..n, parity n..total).
        // `decode_matrix` is the inverse of the n×n submatrix picked from `enc_matrix`
        // rows = available_rows. Recovering data shard i uses enc_matrix row i;
        // recovering parity shard j uses enc_matrix row (n+j). We multiply
        // decode_matrix (n×n, maps available-shards → original data) then re-encode
        // for parity. Concretely: recovered_data = decode_matrix · available_shards;
        // recovered_parity[j] = enc_matrix[(n+j)] · recovered_data. Build the full
        // data vector first.

        // ── Layout offsets (wire-relative; fixed by variant) ────────────
        const suffix: usize = if (set_is_resigned) RETRANSMITTER_SIG_SIZE else 0;
        const chained_sz: usize = if (set_is_chained) MERKLE_ROOT_SIZE else 0;
        // proof bytes from the variant proof_size (already in merkle_proof_sz)
        const proof_bytes: usize = merkle_proof_sz;
        // DATA shred: [0..64]sig [64..proof_start_d-chained]rs [.. ]chained_root [proof_start_d..]proof [tail]resigned
        const proof_start_d: usize = if (DATA_SHRED_WIRE_SIZE > suffix + proof_bytes) DATA_SHRED_WIRE_SIZE - suffix - proof_bytes else 0;
        const chain_off_d: usize = if (proof_start_d >= chained_sz) proof_start_d - chained_sz else 0;
        const data_leaf_end: usize = proof_start_d; // merkle leaf region = [64..proof_start_d] (INCLUDES chained_root)
        // CODE shred offsets (for parity leaves)
        const proof_start_c: usize = if (CODE_SHRED_WIRE_SIZE > suffix + proof_bytes) CODE_SHRED_WIRE_SIZE - suffix - proof_bytes else 0;
        const chain_off_c: usize = if (proof_start_c >= chained_sz) proof_start_c - chained_sz else 0;
        const code_leaf_end: usize = proof_start_c;

        // Common signature (FEC-set signs one merkle root → all shreds share sig).
        var common_sig: [SIGNATURE_SIZE]u8 = undefined;
        var have_sig = false;
        for (0..n) |i| {
            if (set.data_shreds[i]) |t| if (t.len >= SIGNATURE_SIZE) {
                @memcpy(&common_sig, t[0..SIGNATURE_SIZE]);
                have_sig = true;
                break;
            };
        }
        if (!have_sig) for (0..m) |i| {
            if (set.parity_shreds[i]) |t| if (t.len >= SIGNATURE_SIZE) {
                @memcpy(&common_sig, t[0..SIGNATURE_SIZE]);
                have_sig = true;
                break;
            };
        };
        if (!have_sig) return false;

        // Common chained_merkle_root (read from a SURVIVING shred; identical across
        // the FEC set — Agave reads it from the last surviving coding shred,
        // merkle.rs:659; FD captures it once, :877). Read from a data shred's
        // chain_off_d, else a parity shred's chain_off_c.
        var chained_root: [MERKLE_ROOT_SIZE]u8 = undefined;
        if (set_is_chained) {
            var have_cr = false;
            for (0..n) |i| {
                if (set.data_shreds[i]) |t| if (t.len >= chain_off_d + MERKLE_ROOT_SIZE) {
                    @memcpy(&chained_root, t[chain_off_d..][0..MERKLE_ROOT_SIZE]);
                    have_cr = true;
                    break;
                };
            }
            if (!have_cr) for (0..m) |i| {
                if (set.parity_shreds[i]) |t| if (t.len >= chain_off_c + MERKLE_ROOT_SIZE) {
                    @memcpy(&chained_root, t[chain_off_c..][0..MERKLE_ROOT_SIZE]);
                    have_cr = true;
                    break;
                };
            };
            if (!have_cr) return false;
        }

        // Resigned retransmitter signature (FEC-set-common; copied verbatim from a
        // surviving shred's tail — FD :997-1003 uses ctx->retransmitter_sig).
        var retransmit_sig: [RETRANSMITTER_SIG_SIZE]u8 = undefined;
        if (set_is_resigned) {
            var have_rs = false;
            for (0..n) |i| {
                if (set.data_shreds[i]) |t| if (t.len >= DATA_SHRED_WIRE_SIZE) {
                    @memcpy(&retransmit_sig, t[DATA_SHRED_WIRE_SIZE - RETRANSMITTER_SIG_SIZE ..][0..RETRANSMITTER_SIG_SIZE]);
                    have_rs = true;
                    break;
                };
            }
            if (!have_rs) for (0..m) |i| {
                if (set.parity_shreds[i]) |t| if (t.len >= CODE_SHRED_WIRE_SIZE) {
                    @memcpy(&retransmit_sig, t[CODE_SHRED_WIRE_SIZE - RETRANSMITTER_SIG_SIZE ..][0..RETRANSMITTER_SIG_SIZE]);
                    have_rs = true;
                    break;
                };
            };
            if (!have_rs) return false;
        }

        // ── Reconstruct the full DATA-shard vector (RS regions) into temp ──
        // recovered_data[i] = the RS region (length uniform_erasure_sz) of data
        // shred i. For received shreds we already have it in available_shards;
        // but it's simpler+safe to materialize all n data RS regions: received
        // ones copied from their buffer, missing ones via decode_matrix.
        const data_rs = try tmp.alloc([]u8, n);
        for (0..n) |i| {
            const b = try tmp.alloc(u8, uniform_erasure_sz);
            @memset(b, 0);
            data_rs[i] = b;
        }
        // Fill received data RS regions directly from their buffers.
        for (0..n) |i| {
            if (set.data_shreds[i]) |s| {
                if (s.len > data_start) {
                    const avail_end = @min(s.len - @min(rs_trailer, s.len), s.len);
                    const region_len = if (avail_end > data_start) @min(avail_end - data_start, uniform_erasure_sz) else 0;
                    if (region_len > 0) @memcpy(data_rs[i][0..region_len], s[data_start..][0..region_len]);
                }
            }
        }
        // Reconstruct missing data RS regions (decode_matrix row = data index).
        for (missing_indices) |missing_idx| {
            if (missing_idx >= n) continue;
            if (set.data_received.isSet(missing_idx)) continue;
            @memset(data_rs[missing_idx], 0);
            reconstructRegion(self, data_rs[missing_idx], decode_matrix, missing_idx, n, available_shards, uniform_erasure_sz);
        }

        // ── Build all 64 merkle leaves into a temp leaf array ───────────
        // Leaf preimage = the merkle leaf region of the FULLY-STAMPED shred:
        //   data: [64..data_leaf_end] = rs_region ‖ chained_root   (= rs_sz + 32)
        //   code: [64..code_leaf_end] = rs_region ‖ chained_root
        // We assemble each leaf preimage in a scratch buffer (sig is NOT part of
        // the leaf — leaf starts at offset 64). The RS region is data_rs[i] for
        // data, and the parity RS region (received or re-encoded) for code.
        // Leaves are the 20-byte truncated leaf hashes (bmtree.MERKLE_NODE_SIZE):
        // makeMerkleProof builds the tree with hashMerkleNode (which truncates its
        // inputs to 20 B), so the leaf NODES must be the 20-byte form. The tree is
        // byte-identical (first 20 B at every node) to the encoder's 32-byte
        // buildTree32, and the 20-byte root matches reconstructRoot's output.
        const total_leaves = n + m;
        const leaves = try tmp.alloc([bmtree.MERKLE_NODE_SIZE]u8, total_leaves);

        // erasure_sz is the canonical RS shard length (e.g. 987 chained). The leaf
        // region length for data = erasure_sz + chained_sz; assemble accordingly.
        const data_leaf_len: usize = if (data_leaf_end > SIGNATURE_SIZE) data_leaf_end - SIGNATURE_SIZE else 0;
        const code_leaf_len: usize = if (code_leaf_end > SIGNATURE_SIZE) code_leaf_end - SIGNATURE_SIZE else 0;
        if (data_leaf_len == 0 or (m > 0 and code_leaf_len == 0)) {
            std.log.err("[FEC] #61: bad leaf region len (d={d} c={d})", .{ data_leaf_len, code_leaf_len });
            return false;
        }
        // The RS portion inside the leaf region == erasure_sz; the trailing
        // chained_sz bytes are the chained_root. Guard that erasure_sz fits.
        if (erasure_sz + chained_sz != data_leaf_len) {
            // For merkle chained sets these must match the wire layout exactly.
            std.log.err("[FEC] #61: leaf-len mismatch erasure_sz={d}+chained={d} != data_leaf_len={d} (variant layout drift)", .{ erasure_sz, chained_sz, data_leaf_len });
            return false;
        }

        // ── DATA leaves (indices 0..n) ──────────────────────────────────
        // The DATA RS region starts at shred offset 64, so it INCLUDES the
        // 24-byte data header [64..88]; data_rs[i] is exactly the [64..1051]
        // region. The leaf preimage = data_rs[i] ‖ chained_root = [64..1083]
        // (1019 B). Mirrors shred_encoder.zig:165 hashMerkleLeaf32(data[64..1083]).
        {
            const leaf_buf = try tmp.alloc(u8, data_leaf_len);
            for (0..n) |i| {
                @memset(leaf_buf, 0);
                @memcpy(leaf_buf[0..erasure_sz], data_rs[i][0..erasure_sz]); // [64..1051]
                if (set_is_chained) @memcpy(leaf_buf[erasure_sz..][0..MERKLE_ROOT_SIZE], &chained_root); // [1051..1083]
                leaves[i] = bmtree.MerkleTree.hashMerkleLeaf(leaf_buf[0..data_leaf_len]);
            }
        }

        // ── PARITY leaves (indices n..n+m) ──────────────────────────────
        // The CODE RS region starts at offset 89, so the 25-byte CODE HEADER
        // [64..89] is OUTSIDE the RS region and is a SEPARATE part of the leaf
        // preimage. Code leaf = [64..89]header ‖ [89..1076]RS ‖ [1076..1108]chained_root
        // (1044 B). Mirrors shred_encoder.zig:166 hashMerkleLeaf32(code[64..1108])
        // and FD parity_merkle_protected_sz (fd_fec_resolver.c:626, leaf from b+64,
        // reedsol + chained + (CODE_HEADER_SZ - SIG_SZ = 25)).
        //
        // RECEIVED parity j → hash [64..code_leaf_end] straight from its buffer
        //   (header + RS + chained_root all already correct on the wire).
        // MISSING parity j → synthesize: copy the 25-byte code header from a
        //   surviving parity shred (variant/slot/version/fec_set_idx/data_cnt/
        //   code_cnt are FEC-set-common), then patch the two per-shred fields —
        //   common.idx [0x49] = fec_set_idx + j (FD :905) and code.idx [0x57] = j
        //   (FD :910) — then re-encode the RS region and append chained_root.
        // Build the 25-byte template header once (from any surviving parity shred).
        var code_hdr_tmpl: [CODE_HEADER_SIZE - SIGNATURE_SIZE]u8 = undefined; // 25 B: shred[64..89]
        var have_code_hdr = false;
        if (m > 0) {
            for (0..m) |i| {
                if (set.parity_shreds[i]) |s| if (s.len >= CODE_HEADER_SIZE) {
                    @memcpy(&code_hdr_tmpl, s[SIGNATURE_SIZE..CODE_HEADER_SIZE]);
                    have_code_hdr = true;
                    break;
                };
            }
            if (!have_code_hdr) {
                // Cannot synthesize missing-parity leaves without a header template;
                // but if ALL parity leaves are present from buffers we don't need it.
                var any_missing_parity = false;
                for (0..m) |j| {
                    if (set.parity_shreds[j] == null) {
                        any_missing_parity = true;
                        break;
                    }
                }
                if (any_missing_parity) {
                    std.log.warn("[FEC] #61: no surviving parity shred for code-header template — cannot rebuild tree", .{});
                    return false;
                }
            }
        }

        {
            const leaf_buf = try tmp.alloc(u8, code_leaf_len);
            for (0..m) |j| {
                if (set.parity_shreds[j]) |s| {
                    // Received: hash the leaf region straight from the wire buffer.
                    if (s.len < code_leaf_end) {
                        std.log.warn("[FEC] #61: parity shred {d} too short ({d} < {d})", .{ j, s.len, code_leaf_end });
                        return false;
                    }
                    leaves[n + j] = bmtree.MerkleTree.hashMerkleLeaf(s[SIGNATURE_SIZE..code_leaf_end]);
                } else {
                    // Missing: synthesize header + re-encoded RS + chained_root.
                    @memset(leaf_buf, 0);
                    // [0..25] code header (offset 64..89 within the shred).
                    @memcpy(leaf_buf[0 .. CODE_HEADER_SIZE - SIGNATURE_SIZE], &code_hdr_tmpl);
                    // Patch per-shred header fields (offsets relative to shred[64]):
                    //   common.idx at shred[0x49] → leaf_buf[0x49-0x40 = 9]
                    std.mem.writeInt(u32, leaf_buf[0x09..][0..4], @as(u32, @intCast(set.fec_set_idx + j)), .little);
                    //   code.idx (position) at shred[0x57] → leaf_buf[0x57-0x40 = 0x17 = 23]
                    std.mem.writeInt(u16, leaf_buf[0x17..][0..2], @as(u16, @intCast(j)), .little);
                    // RS region [25..25+erasure_sz] (offset 89..1076 within shred).
                    const rs_off = CODE_HEADER_SIZE - SIGNATURE_SIZE; // 25
                    for (0..n) |dcol| {
                        const coeff = enc_matrix[(n + j) * n + dcol];
                        if (coeff == 0) continue;
                        self.simd.mulAccum(leaf_buf[rs_off..][0..erasure_sz], data_rs[dcol][0..erasure_sz], coeff);
                    }
                    // chained_root at [rs_off+erasure_sz ..][0..32] (offset 1076..1108).
                    if (set_is_chained) @memcpy(leaf_buf[rs_off + erasure_sz ..][0..MERKLE_ROOT_SIZE], &chained_root);
                    leaves[n + j] = bmtree.MerkleTree.hashMerkleLeaf(leaf_buf[0..code_leaf_len]);
                }
            }
        }

        // ── Surviving SIGNED merkle root (20-byte, from a received shred) ─
        // Compute from a surviving shred's leaf + its embedded proof at its FEC
        // index. This is the leader-signed root that recovered shreds must hash
        // up to (Agave merkle.rs:795 `tree.last() == merkle_root`).
        var signed_root20: [MERKLE_ROOT_SIZE]u8 = undefined; // first 20 bytes meaningful
        var have_signed = false;
        // Prefer a surviving DATA shred (leaf index = its FEC position).
        for (0..n) |i| {
            if (have_signed) break;
            if (set.data_shreds[i]) |s| {
                if (s.len >= proof_start_d + proof_bytes and proof_start_d >= SIGNATURE_SIZE) {
                    const leaf20 = bmtree.MerkleTree.hashMerkleLeaf(s[SIGNATURE_SIZE..data_leaf_end]);
                    const proof_nodes = s[proof_start_d..][0..proof_bytes];
                    const r = bmtree.MerkleTree.reconstructRoot(leaf20, proof_nodes, i);
                    @memcpy(signed_root20[0..MERKLE_PROOF_ENTRY_SIZE], &r);
                    have_signed = true;
                }
            }
        }
        if (!have_signed) for (0..m) |j| {
            if (have_signed) break;
            if (set.parity_shreds[j]) |s| {
                if (s.len >= proof_start_c + proof_bytes and proof_start_c >= SIGNATURE_SIZE) {
                    const leaf20 = bmtree.MerkleTree.hashMerkleLeaf(s[SIGNATURE_SIZE..code_leaf_end]);
                    const proof_nodes = s[proof_start_c..][0..proof_bytes];
                    const r = bmtree.MerkleTree.reconstructRoot(leaf20, proof_nodes, n + j);
                    @memcpy(signed_root20[0..MERKLE_PROOF_ENTRY_SIZE], &r);
                    have_signed = true;
                }
            }
        };
        if (!have_signed) {
            std.log.warn("[FEC] #61: no surviving shred to derive signed merkle root — skipping recovery", .{});
            return false;
        }

        // ── Build the tree over all 64 leaves + per-recovered-data proofs ─
        // makeMerkleProof builds the full 64-leaf tree and returns the 20-byte
        // root + the proof for the requested leaf. We compute the proof for each
        // recovered DATA shred (the only shreds the downstream consumer reads),
        // and use the returned root for the consensus GATE.
        var rebuilt_root20: ?[MERKLE_PROOF_ENTRY_SIZE]u8 = null;
        // Scratch proof buffer per recovered shred.
        const proof_entries: usize = proof_bytes / MERKLE_PROOF_ENTRY_SIZE;
        const proof_scratch = try tmp.alloc([MERKLE_PROOF_ENTRY_SIZE]u8, @max(proof_entries, 1));
        // Stash recovered DATA shred buffers + their proofs until the gate passes.
        const recovered_bufs = try tmp.alloc(?[]u8, n);
        for (0..n) |i| recovered_bufs[i] = null;
        const recovered_proofs = try tmp.alloc([][MERKLE_PROOF_ENTRY_SIZE]u8, n);

        var any_recovered = false;
        for (missing_indices) |missing_idx| {
            if (missing_idx >= n) continue;
            if (set.data_received.isSet(missing_idx)) continue;

            // Variant sanity: the reconstructed RS region's variant byte (offset
            // 64-data_start within the RS region == byte at index 0 of header...).
            // The RS region begins at the shred byte after `data_start` (=64 for
            // data). The variant byte lives at shred[64], i.e. RS region[0].
            const variant_byte = data_rs[missing_idx][0];
            const is_valid_data = (variant_byte >= 0x80 and variant_byte <= 0xBF) or variant_byte == 0xA5;
            if (!is_valid_data) {
                std.log.debug("[FEC] #61 recovered idx={d} variant=0x{x:0>2} not a data shred, skipping", .{ missing_idx, variant_byte });
                continue;
            }

            // Build the inclusion proof + root for this recovered data leaf.
            const root = bmtree.MerkleTree.makeMerkleProof(tmp, leaves, missing_idx, proof_scratch[0..proof_entries]) catch {
                std.log.warn("[FEC] #61 makeMerkleProof failed idx={d}", .{missing_idx});
                return false;
            };
            if (rebuilt_root20 == null) rebuilt_root20 = root;

            // Allocate the final recovered DATA shred buffer (MAIN allocator —
            // outlives the arena; ownership transfers to set.data_shreds on commit).
            var buf = self.allocator.alloc(u8, DATA_SHRED_WIRE_SIZE) catch return false;
            @memset(buf, 0);
            @memcpy(buf[0..SIGNATURE_SIZE], &common_sig); // FEC-set-common sig
            @memcpy(buf[data_start..][0..erasure_sz], data_rs[missing_idx][0..erasure_sz]); // RS region
            if (set_is_chained) @memcpy(buf[chain_off_d..][0..MERKLE_ROOT_SIZE], &chained_root);
            // proof written AFTER the gate (below) — keep proof bytes for now.
            const pcopy = tmp.alloc([MERKLE_PROOF_ENTRY_SIZE]u8, proof_entries) catch return false;
            for (0..proof_entries) |pe| pcopy[pe] = proof_scratch[pe];
            recovered_proofs[missing_idx] = pcopy;
            recovered_bufs[missing_idx] = buf;
            any_recovered = true;
        }

        if (!any_recovered) {
            // Nothing to do (all "missing" turned out non-data / already present).
            return set.isComplete();
        }

        // ── CONSENSUS GATE: rebuilt root must == surviving signed root ──
        // This REPLACES per-shred ed25519 verification (Agave merkle.rs:792-797 /
        // FD :929). A bad RS reconstruct, wrong chained_root, or header drift makes
        // the rebuilt tree's root differ → REJECT the WHOLE set (insert NOTHING),
        // leave it .pending so repair fetches genuine shreds. Compare 20 bytes
        // (the wire proof-node width); the surviving root was reduced to 20 bytes
        // via reconstructRoot, and makeMerkleProof returns a 20-byte root.
        const gate_ok = if (rebuilt_root20) |rr|
            std.mem.eql(u8, rr[0..MERKLE_PROOF_ENTRY_SIZE], signed_root20[0..MERKLE_PROOF_ENTRY_SIZE])
        else
            false;

        if (!gate_ok) {
            std.log.warn("[FEC] #61 ROOT-GATE REJECT slot={d} fec={d}: rebuilt root != signed root — discarding recovered set (repair will fill)", .{ set.slot, set.fec_set_idx });
            // Free all staged recovered buffers; insert nothing.
            for (0..n) |i| if (recovered_bufs[i]) |b| self.allocator.free(b);
            self.stats.recovery_failures += 1;
            return false;
        }

        // ── COMMIT (gate passed): write proofs + resigned sig, install ──
        var recovered_count: usize = 0;
        for (0..n) |i| {
            const buf = recovered_bufs[i] orelse continue;
            // Merkle proof bytes (proof_entries × 20) at proof_start_d.
            for (0..proof_entries) |pe| {
                @memcpy(buf[proof_start_d + pe * MERKLE_PROOF_ENTRY_SIZE ..][0..MERKLE_PROOF_ENTRY_SIZE], &recovered_proofs[i][pe]);
            }
            // Resigned retransmitter signature at the shred tail.
            if (set_is_resigned) {
                @memcpy(buf[DATA_SHRED_WIRE_SIZE - RETRANSMITTER_SIG_SIZE ..][0..RETRANSMITTER_SIG_SIZE], &retransmit_sig);
            }
            set.data_shreds[i] = buf;
            set.data_received.set(@intCast(i));
            set.data_received_cnt += 1;
            recovered_count += 1;
        }

        if (recovered_count > 0) {
            std.log.info("[FEC] #61 Recovered {d}/{d} data shreds (chained={any} resigned={any} simd={any} erasure_sz={d} n={d} m={d}) — root gate PASS", .{
                recovered_count, k, set_is_chained, set_is_resigned, self.enable_simd_fec, erasure_sz, n, m,
            });
        }
        return recovered_count > 0;
    }

    /// Remove a completed FEC set to free memory
    /// Data-shred count of a FEC set, or null if unknown (set absent, or its
    /// erasure config not yet learned — data_shred_cnt is set from a coding-shred
    /// header / on completion). Used by the SIMD-0340 chain tracker to compute
    /// arithmetic FEC adjacency (next.fec_set_index == this.fec_set_index + num_data).
    pub fn getNumData(self: *Self, slot: core.Slot, fec_set_idx: u32) ?u16 {
        // THREAD SAFETY (2026-06-14): reads active_sets + a *FecSet field, which
        // the recv-thread addShred eviction can free concurrently. Lock. *Self
        // (not *const) is required to take the mutex. See fec_mutex doc.
        self.fec_mutex.lock();
        defer self.fec_mutex.unlock();
        const key = makeKey(slot, fec_set_idx);
        if (self.active_sets.get(key)) |set| {
            if (set.data_shred_cnt > 0) return set.data_shred_cnt;
        }
        return null;
    }

    pub fn removeSet(self: *Self, slot: core.Slot, fec_set_idx: u32) void {
        const key = makeKey(slot, fec_set_idx);
        if (self.active_sets.fetchRemove(key)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// Remove all FEC sets for a slot
    pub fn removeSlot(self: *Self, slot: core.Slot) void {
        var to_remove = std.ArrayListUnmanaged(FecSetKey){};
        defer to_remove.deinit(self.allocator);

        var it = self.active_sets.iterator();
        while (it.next()) |entry| {
            if (@as(u64, @intCast(entry.key_ptr.* >> 64)) == slot) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.active_sets.fetchRemove(key)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "galois field basic operations" {
    const gf = GaloisField.init();

    // Test identity
    try std.testing.expectEqual(@as(u8, 1), gf.mul(1, 1));

    // Test commutativity
    try std.testing.expectEqual(gf.mul(5, 7), gf.mul(7, 5));

    // Test inverse
    for (1..256) |i| {
        const x: u8 = @intCast(i);
        const inv_x = gf.inv(x);
        try std.testing.expectEqual(@as(u8, 1), gf.mul(x, inv_x));
    }
}

test "fec set basic operations" {
    const allocator = std.testing.allocator;

    var set = FecSet.init(allocator, 12345, 0);
    defer set.deinit();

    // Add some data shreds
    var data1: [100]u8 = undefined;
    @memset(&data1, 0xAA);
    try set.addDataShred(0, &data1);

    try std.testing.expectEqual(@as(u16, 1), set.data_received_cnt);
    try std.testing.expect(set.data_received.isSet(0));
}

test "isChainedVariant: chained vs non-chained merkle variant classification" {
    // Chained merkle data: 0x90 (chained), 0xB0 (chained+resigned) — low nibble = proof_size.
    try std.testing.expect(isChainedVariant(0x90));
    try std.testing.expect(isChainedVariant(0x9F));
    try std.testing.expect(isChainedVariant(0xB0));
    try std.testing.expect(isChainedVariant(0xB5));
    // Chained merkle code: 0x60 (chained), 0x70 (chained+resigned).
    try std.testing.expect(isChainedVariant(0x60));
    try std.testing.expect(isChainedVariant(0x70));
    try std.testing.expect(isChainedVariant(0x6A));
    // Alpenglow V3 chained.
    try std.testing.expect(isChainedVariant(0x58));
    // NON-chained merkle: 0x80 (data), 0x40 (code).
    try std.testing.expect(!isChainedVariant(0x80));
    try std.testing.expect(!isChainedVariant(0x85));
    try std.testing.expect(!isChainedVariant(0x40));
    try std.testing.expect(!isChainedVariant(0x4A));
    // Legacy variants are not chained merkle.
    try std.testing.expect(!isChainedVariant(0xA5)); // legacy data
    try std.testing.expect(!isChainedVariant(0x5A)); // legacy code
}

// ═══════════════════════════════════════════════════════════════════════════════
// #61 CHAINED-MERKLE FEC RECOVERY — REAL-VECTOR KAT
// Run: zig build test-fec-recovery
//
// VECTOR SOURCE: the repo's OWN shred encoder (shred_encoder.zig assembleFecSet),
// which produces a self-consistent CHAINED (non-resigned) 32-data + 32-code FEC set
// whose every shred's leaf+embedded-proof reconstructs to the leader-signed merkle
// root (that round-trip is itself gated by shred_encoder's KAT against the SAME
// receive-side reconstructRoot used in consensus). No real on-chain *.bin chained-FEC
// vector exists in the repo (kat-ground-truth holds account/vote/elf goldens only;
// FD demo-shreds.pcap is legacy non-chained) — so we synthesize. This is NOT
// circular: the encoder uses shred_reedsol.encodeParity + buildTree32, while recovery
// uses an INDEPENDENT Vandermonde decode (recoverWithSigMethod) + makeMerkleProof +
// reconstructRoot. Agreement across those three independent tree/RS paths is the gate.
//
// @prov:fec.chained-merkle-recovery
// ═══════════════════════════════════════════════════════════════════════════════

const shred_encoder = @import("shred_encoder.zig");
const shred_layout = @import("shred_layout.zig");

/// Drive a full set of data + code shreds into the resolver, optionally skipping
/// (erasing) certain data positions and parity positions. fec_set_idx is 0 so a
/// data shred's FEC position == its index. Returns the AddResult of the LAST add.
fn katFeedSet(
    resolver: *FecResolver,
    set: *const shred_encoder.FecSetShreds,
    slot: core.Slot,
    erase_data: []const usize,
    erase_parity: []const usize,
) !FecResolver.AddResult {
    const N = set.data.len;
    const M = set.code.len;
    var last: FecResolver.AddResult = .pending;

    const isErased = struct {
        fn f(list: []const usize, x: usize) bool {
            for (list) |e| if (e == x) return true;
            return false;
        }
    }.f;

    // Data shreds. idx = data_start_idx(0) + i, fec_set_idx = 0 → pos = i.
    for (0..N) |i| {
        if (isErased(erase_data, i)) continue;
        last = try resolver.addShred(
            slot,
            @intCast(i), // shred_index
            0, // fec_set_idx
            true, // is_data
            set.data[i],
            57087, // shred_version
            @intCast(N),
            @intCast(M),
            0, // parity_position (unused for data)
        );
    }
    // Parity shreds. parity_position = code.idx (0x57) = j. num_data/num_parity from header.
    for (0..M) |j| {
        if (isErased(erase_parity, j)) continue;
        last = try resolver.addShred(
            slot,
            @intCast(j), // shred_index (unused for parity placement)
            0, // fec_set_idx
            false, // is_data
            set.code[j],
            57087,
            @intCast(N),
            @intCast(M),
            @intCast(j), // parity_position
        );
    }
    return last;
}

/// Build the canonical chained, non-resigned 32:32 FEC set used by both KAT cases.
fn katBuildChainedSet(allocator: std.mem.Allocator) !shred_encoder.FecSetShreds {
    const Ed25519 = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast((i * 13 + 7) & 0xFF);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const sk = kp.secret_key.toBytes();

    const dpp = shred_layout.dataShredPayloadSz(6, true, false); // 963
    const total_payload = shred_layout.FEC_SHRED_CNT * dpp; // 32*963
    const payload = try allocator.alloc(u8, total_payload);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 131 + 17) & 0xFF);

    var chained: [shred_encoder.ROOT_SZ]u8 = undefined;
    for (&chained, 0..) |*b, i| b.* = @intCast((i * 9 + 1) & 0xFF);

    return try shred_encoder.assembleFecSet(allocator, .{
        .slot = 415266588, // the live wedge slot from the #61 plan
        .version = 57087,
        .fec_set_idx = 0,
        .data_start_idx = 0,
        .code_start_idx = 0,
        .parent_off = 1,
        .reference_tick = 5,
        .data_complete = true,
        .slot_complete = false,
    }, payload, chained, sk);
}

/// POSITIVE: erase several DATA *and* several PARITY shreds, recover, then assert
/// (a) recovered payload bytes == original wire bytes, (b) rebuilt merkle root ==
/// original signed root (verified via reconstructRootFull over the embedded proof,
/// the strong form — same path the encoder KAT uses), (c) recovered chained_root ==
/// original. Erasing parity too exercises the missing-parity-leaf synthesis branch
/// (fec_resolver.zig:1380-1400) that feeds the consensus root gate. Run on BOTH the
/// scalar and SIMD reconstruct paths.
fn katPositive(comptime use_simd: bool) !void {
    const allocator = std.testing.allocator;

    var orig = try katBuildChainedSet(allocator);
    defer orig.deinit(allocator);

    // Independent copy of the set to feed (resolver takes its own copies via
    // addDataShred/addParityShred, but we erase by NOT feeding — `orig` stays pristine
    // for the byte comparison).
    var resolver = if (use_simd)
        FecResolver.initWithSimd(allocator, 64, 57087)
    else
        FecResolver.init(allocator, 64, 57087);
    defer resolver.deinit();

    const slot: core.Slot = 415266588;
    // Erase 6 data + 6 parity. Survivors: 26 data + 26 parity = 52 >= 32 needed;
    // 6 missing data <= 26 parity available. data[0] kept (signed-root source).
    const erase_data = [_]usize{ 3, 7, 11, 19, 23, 30 };
    const erase_parity = [_]usize{ 0, 5, 9, 14, 21, 28 };

    const last = try katFeedSet(&resolver, &orig, slot, &erase_data, &erase_parity);
    try std.testing.expectEqual(FecResolver.AddResult.complete, last);

    // Pull the recovered FEC set back out.
    const key = FecResolver.makeKey(slot, 0);
    const set = resolver.active_sets.get(key) orelse return error.SetMissing;
    try std.testing.expect(set.isComplete());
    try std.testing.expectEqual(@as(u16, 32), set.data_received_cnt);

    const proof_bytes: usize = 6 * bmtree.MERKLE_NODE_SIZE; // depth 6 -> 120
    const proof_start = DATA_SHRED_WIRE_SIZE - proof_bytes; // 1083

    for (erase_data) |idx| {
        const rec = set.data_shreds[idx] orelse return error.RecoveredShredMissing;
        try std.testing.expectEqual(DATA_SHRED_WIRE_SIZE, rec.len);

        // (a) recovered payload bytes == original wire bytes (full slice).
        try std.testing.expectEqualSlices(u8, orig.data[idx], rec);

        // (b) rebuilt merkle root == original signed root (strong form: hash the
        // recovered leaf, walk the embedded proof, must reconstruct to set.root 32B).
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(rec[64..proof_start]);
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, rec[proof_start..], idx);
        try std.testing.expectEqualSlices(u8, &orig.root, &r);

        // (c) recovered chained_merkle_root == original. Wire layout (chained, non-
        // resigned): chained_root sits at [proof_start-32 .. proof_start] = [1051..1083].
        // (Same offset Shred.chainedMerkleRoot() reads; exercises the FIX-#56 region.)
        const rec_chained = rec[proof_start - 32 .. proof_start];
        const orig_chained = orig.data[idx][proof_start - 32 .. proof_start];
        try std.testing.expectEqualSlices(u8, orig_chained, rec_chained);
    }
}

test "#61 chained FEC recovery KAT (scalar): recovered bytes + merkle root + chained_root == original" {
    try katPositive(false);
}

test "#61 chained FEC recovery KAT (SIMD): recovered bytes + merkle root + chained_root == original" {
    try katPositive(true);
}

test "incident-422359406: recovering the DATA_COMPLETE-bearing shred (last data shred, flags byte 85 = 0x40) reproduces byte 85 exactly" {
    // katPositive's erase_data = {3,7,11,19,23,30} never includes index 31 —
    // the LAST data shred of a 32-shred set, the ONE shred
    // shred_encoder.assembleFecSet stamps with the 0x40 DATA_COMPLETE bit
    // (assembleFecSet: `is_last and params.data_complete` -> flags |=
    // DATA_FLAG_DATA_COMPLETE, shred_encoder.zig:109). The incident-422359406
    // postmortem hypothesized a FEC-recovered shred's flags byte (85) could
    // come back wrong after Reed-Solomon reconstruction. This KAT erases
    // EXACTLY that shred and asserts recovery reproduces it byte-for-byte,
    // including byte 85's 0x40 bit specifically — closing the one gap
    // katPositive's erase set left untested (it never erased the
    // flags-bearing shred itself).
    const allocator = std.testing.allocator;

    var orig = try katBuildChainedSet(allocator);
    defer orig.deinit(allocator);

    // Sanity: the encoder actually set 0x40 on shred 31, not slot_complete's
    // 0x80 (katBuildChainedSet passes data_complete=true, slot_complete=false).
    try std.testing.expectEqual(@as(u8, 0x40), orig.data[31][85] & 0xC0);

    var resolver = FecResolver.init(allocator, 64, 57087);
    defer resolver.deinit();

    const slot: core.Slot = 415266589;
    const erase_data = [_]usize{31};
    const erase_parity = [_]usize{}; // full 32 parity shreds available (>=1 needed)

    const last = try katFeedSet(&resolver, &orig, slot, &erase_data, &erase_parity);
    try std.testing.expectEqual(FecResolver.AddResult.complete, last);

    const key = FecResolver.makeKey(slot, 0);
    const set = resolver.active_sets.get(key) orelse return error.SetMissing;
    const rec = set.data_shreds[31] orelse return error.RecoveredShredMissing;

    // The specific byte + bit the incident hypothesized as corruptible.
    try std.testing.expectEqual(orig.data[31][85], rec[85]);
    try std.testing.expectEqual(@as(u8, 0x40), rec[85] & 0xC0);
    // Full-buffer byte-exactness (superset of the above, belt-and-suspenders).
    try std.testing.expectEqualSlices(u8, orig.data[31], rec);
}

test "#61 chained FEC recovery KAT (negative): corrupted survivor → root gate REJECT, no shred installed" {
    const allocator = std.testing.allocator;

    var orig = try katBuildChainedSet(allocator);
    defer orig.deinit(allocator);

    var resolver = FecResolver.init(allocator, 64, 57087);
    defer resolver.deinit();

    const slot: core.Slot = 777777;
    const N = orig.data.len;
    const M = orig.code.len;

    // Plan: keep data[0] PRISTINE (it is the signed-root source, fec_resolver.zig:1411),
    // CORRUPT a DIFFERENT surviving data shred's RS region (data[5]) so the rebuilt
    // tree's root will differ from the signed root, and ERASE a third (data[10]) so a
    // recovery is actually attempted. The corrupted survivor poisons the rebuilt root
    // → gate (rebuilt root != signed root) must REJECT the whole set (insert nothing).
    const corrupt_idx: usize = 5;
    const erased_idx: usize = 10;

    const isErased = struct {
        fn f(x: usize, e: usize) bool {
            return x == e;
        }
    }.f;

    // Feed data shreds, corrupting data[5]'s RS region (a byte well inside the
    // RS-coded payload, NOT in the header/proof, so it changes the leaf hash and the
    // RS-decode of the erased shred but is still parsed as a valid data shred).
    for (0..N) |i| {
        if (isErased(i, erased_idx)) continue;
        if (i == corrupt_idx) {
            const tmp = try allocator.alloc(u8, orig.data[i].len);
            defer allocator.free(tmp);
            @memcpy(tmp, orig.data[i]);
            tmp[300] ^= 0xFF; // flip a byte in the RS-coded payload region
            _ = try resolver.addShred(slot, @intCast(i), 0, true, tmp, 57087, @intCast(N), @intCast(M), 0);
        } else {
            _ = try resolver.addShred(slot, @intCast(i), 0, true, orig.data[i], 57087, @intCast(N), @intCast(M), 0);
        }
    }
    // Feed ALL parity shreds (so recovery is triggered for the one erased data shred).
    var last: FecResolver.AddResult = .pending;
    for (0..M) |j| {
        last = try resolver.addShred(slot, @intCast(j), 0, false, orig.code[j], 57087, @intCast(N), @intCast(M), @intCast(j));
    }

    // The set must NOT be reported complete (gate rejected the recovery).
    try std.testing.expect(last != .complete);

    const key = FecResolver.makeKey(slot, 0);
    const set = resolver.active_sets.get(key) orelse return error.SetMissing;
    // The erased shred must NOT have been installed.
    try std.testing.expect(set.data_shreds[erased_idx] == null);
    try std.testing.expect(!set.data_received.isSet(erased_idx));
    // 31 fed data shreds (one erased); recovery rejected → still 31, never 32.
    try std.testing.expectEqual(@as(u16, 31), set.data_received_cnt);
    try std.testing.expect(!set.isComplete());
    // The root gate must have counted a recovery failure.
    try std.testing.expect(resolver.stats.recovery_failures >= 1);
}
