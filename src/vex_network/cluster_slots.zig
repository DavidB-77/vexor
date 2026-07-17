//! cluster_slots.zig — bounded, thread-safe slot -> {advertiser peers} index for
//! SLOT-AWARE REPAIR PEER SELECTION.
//!
//! WHY (2026-06-14 carrier — AF_XDP repair dead-end): a sub-threshold FEC set's
//! missing DATA shred (slot 415380972 idx 97) got 256k WindowIndex requests but
//! ~0 served, wedging the consensus root. Root cause: getRepairPeers (tvu.zig)
//! ignored the slot and round-robined ALL gossip peers, so for a slot held by few
//! peers it rarely asked one that had it. Agave instead weights repair peers by who
//! ADVERTISES the slot via EpochSlots gossip (cluster_slots.rs). Vexor DISCARDED
//! EpochSlots; this index restores it.
//!
//! This is a REDUCED port of Agave core/src/cluster_slots_service/cluster_slots.rs:
//!   - NO epoch-stake weighting (Vexor repair has no epoch_stakes wired and the task
//!     forbids touching consensus state). Weighting is by PRESENCE only: a peer that
//!     advertises the slot is preferred over one that does not.
//!   - Bounded by a SLOT WINDOW relative to root, mirroring CLUSTER_SLOTS_TRIM_SIZE
//!     (cluster_slots.rs:31) and roll_cluster_slots (cluster_slots.rs:260).
//!
//! REPAIR-TARGETING METADATA ONLY. It NEVER feeds bank_hash / consensus / shred
//! validation / vote / replay. A wrong entry only changes WHO we ask for repair,
//! never what we accept.

const std = @import("std");

/// Live-window size, in slots, above the current root. Mirrors Agave
/// CLUSTER_SLOTS_TRIM_SIZE (cluster_slots.rs:31). Entries with slot <= root or
/// slot > root + SLOT_WINDOW are dropped on insert and pruned on setRoot.
pub const SLOT_WINDOW: u64 = 50_000;

/// Per-slot advertiser cap. Bounds per-slot memory and repair fanout. Worst-case
/// footprint = SLOT_WINDOW * MAX_PEERS_PER_SLOT * 32B = 50000*32*32 ~= 50MB hard
/// ceiling, independent of gossip volume or attacker behavior.
pub const MAX_PEERS_PER_SLOT: usize = 32;

const Pubkey = [32]u8;

const SlotPeers = struct {
    // Fixed inline array + count (std.BoundedArray was removed in Zig 0.15.2).
    peers: [MAX_PEERS_PER_SLOT]Pubkey = undefined,
    count: usize = 0,

    fn slice(self: *const SlotPeers) []const Pubkey {
        return self.peers[0..self.count];
    }

    fn contains(self: *const SlotPeers, pk: Pubkey) bool {
        for (self.slice()) |*p| {
            if (std.mem.eql(u8, p, &pk)) return true;
        }
        return false;
    }

    fn append(self: *SlotPeers, pk: Pubkey) void {
        if (self.count >= MAX_PEERS_PER_SLOT) return; // full -> drop (bounded)
        self.peers[self.count] = pk;
        self.count += 1;
    }
};

pub const ClusterSlots = struct {
    mutex: std.Thread.Mutex = .{},
    /// Current root. Live window is (root, root + SLOT_WINDOW].
    root: u64 = 0,
    map: std.AutoHashMapUnmanaged(u64, SlotPeers) = .{},
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.map.deinit(self.allocator);
    }

    /// Record that `from` advertises `slot`. Drops out-of-window slots
    /// (Agave slot_range filter cluster_slots.rs:376-378). Deduped; capped at
    /// MAX_PEERS_PER_SLOT advertisers per slot. Allocation failure is swallowed
    /// (advisory index — a missed insert only costs a sub-optimal peer choice).
    pub fn insert(self: *Self, slot: u64, from: Pubkey) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.insertLocked(slot, from);
    }

    /// Caller already holds self.mutex. Used by insertMany to amortise the lock
    /// over an entire CompressedSlots entry (up to 16384 bits) rather than
    /// re-acquiring per bit (gossip hot path).
    fn insertLocked(self: *Self, slot: u64, from: Pubkey) void {
        if (slot <= self.root or slot > self.root + SLOT_WINDOW) return;
        const gop = self.map.getOrPut(self.allocator, slot) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const sp = gop.value_ptr;
        if (sp.contains(from)) return;
        sp.append(from); // full -> drop (bounded fanout)
    }

    /// Insert all slots in `slots` for advertiser `from` under a SINGLE lock
    /// acquisition (gossip ingest calls this once per CompressedSlots entry).
    pub fn insertMany(self: *Self, slots: []const u64, from: Pubkey) void {
        if (slots.len == 0) return;
        // LOCK-CHUNK (2026-06-16): release self.mutex every CHUNK slots instead of
        // holding it over the whole CompressedSlots batch (was up to 16384 slots).
        // The repair path (lookupPeers/isAdvertiser, getRepairPeers hot path) takes
        // the SAME mutex; a long hold here blocked repair → missing shreds not
        // requested → replay fell behind → delinquent (post-restart EpochSlots
        // flood). Chunking bounds the worst-case repair wait to CHUNK inserts while
        // keeping the lock amortised vs per-bit re-acquire. Canonical: Agave never
        // holds a global lock across a whole peer's EpochSlots update.
        const CHUNK: usize = 256;
        var i: usize = 0;
        while (i < slots.len) {
            const end = @min(i + CHUNK, slots.len);
            self.mutex.lock();
            for (slots[i..end]) |slot| self.insertLocked(slot, from);
            self.mutex.unlock();
            i = end;
        }
    }

    /// True if `pubkey` is a known advertiser of `slot`. Mirrors Agave lookup
    /// (cluster_slots.rs:124).
    pub fn isAdvertiser(self: *Self, slot: u64, pubkey: Pubkey) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const sp = self.map.getPtr(slot) orelse return false;
        return sp.contains(pubkey);
    }

    /// Copy advertisers of `slot` into `out`, returning the filled prefix.
    pub fn lookupPeers(self: *Self, slot: u64, out: []Pubkey) []Pubkey {
        self.mutex.lock();
        defer self.mutex.unlock();
        const sp = self.map.getPtr(slot) orelse return out[0..0];
        const src = sp.slice();
        const n = @min(src.len, out.len);
        @memcpy(out[0..n], src[0..n]);
        return out[0..n];
    }

    /// Advance the root and prune every entry outside (new_root, new_root +
    /// SLOT_WINDOW]. Vexor analogue of roll_cluster_slots (cluster_slots.rs:260),
    /// bounding the map to at most SLOT_WINDOW live entries. Monotonic: ignores a
    /// non-increasing root. Called at the existing root-advance/prune cadence.
    pub fn setRoot(self: *Self, new_root: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (new_root <= self.root) return;
        self.root = new_root;
        // Collect keys to remove (cannot remove during iteration).
        var to_remove: std.ArrayListUnmanaged(u64) = .{};
        defer to_remove.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const slot = entry.key_ptr.*;
            if (slot <= new_root or slot > new_root + SLOT_WINDOW) {
                to_remove.append(self.allocator, slot) catch {
                    // OOM collecting prune list: best-effort, removed below what we have.
                    break;
                };
            }
        }
        for (to_remove.items) |slot| _ = self.map.remove(slot);
    }

    /// Live entry count (test/diagnostic).
    pub fn len(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.count();
    }
};

/// SLOT-AWARE REPAIR diagnostics (v1). All written ONLY on the single gossip
/// ingest thread (handlePush/handlePullResponse), so plain globals are fine —
/// no atomics needed. `flate2_skipped` is the load-bearing one: it counts Flate2
/// CompressedSlots entries we size-walked but did NOT slot-extract (v1 skips
/// inflate). It is the production instrument for the v1 design assumption "the
/// freshest tip slots live in the trailing Uncompressed entry" — if repair is
/// still wedging AND this number is large relative to uncompressed_entries, the
/// tip slots are in Flate2 and v2 (raw-deflate inflate) is required.
pub var flate2_skipped: u64 = 0;
pub var uncompressed_entries: u64 = 0; // Uncompressed CompressedSlots entries ingested
pub var epochslots_values: u64 = 0; // EpochSlots CrdsValues successfully walked

/// Default-ON safety valve for the EpochSlots→ClusterSlots ingest (canonical
/// slot-aware repair — stays ON). The real fix for the replay-starvation it
/// caused post-restart is (1) lock-chunked insertMany (below) so the repair path
/// is never blocked for long, and (2) dedicated-core tiling so gossip never
/// shares a core with replay. This env is an OPS escape hatch only:
/// VEX_EPOCHSLOTS_INGEST=0 disables ingest in an emergency. -1=unread,0=off,1=on.
var es_ingest_cache: i8 = -1;
fn epochSlotsIngestEnabled() bool {
    if (es_ingest_cache < 0) {
        const v = std.posix.getenv("VEX_EPOCHSLOTS_INGEST");
        // Default ON; only an explicit "0" disables it.
        es_ingest_cache = if (v != null and std.mem.eql(u8, v.?, "0")) 0 else 1;
    }
    return es_ingest_cache == 1;
}

/// Periodic one-line diagnostic, throttled to every `every`-th EpochSlots value.
/// Call from the gossip ingest thread after a successful walk.
pub fn logIngestStats(every: u64) void {
    epochslots_values +|= 1;
    if (every == 0 or epochslots_values % every == 0) {
        std.log.debug(
            "[CLUSTER-SLOTS] EpochSlots ingested={d} uncompressed_entries={d} flate2_skipped(v1)={d}",
            .{ epochslots_values, uncompressed_entries, flate2_skipped },
        );
    }
}

/// SLOT-AWARE REPAIR (2026-06-14): exact-size walker + optional ingest for a
/// CrdsData::EpochSlots (tag 5) CrdsValue. `data` starts at the CrdsValue
/// signature (64 bytes), matching gossip.zig's getCrdsValueSize convention.
/// Returns the EXACT byte size of the whole CrdsValue (sig(64)+tag(4)+EpochSlots
/// body) so the packet walker no longer desyncs, or null on any short/oversized
/// read (NEVER panics — a hostile gossip packet must not crash the validator).
///
/// When `cs` is non-null, every set-bit slot in each Uncompressed CompressedSlots
/// entry is inserted as advertised by `from`, under a SINGLE lock per entry.
///
/// Wire layout (verified byte-for-byte against an Agave 4.1.0-beta.3
/// `bincode::serialize(&CrdsData::EpochSlots(ix, es))` dump — see the KAT below):
///   sig(64) tag(u32=5) index(u8) from(32) slots_vec_len(u64)
///     N * CompressedSlots
///   wallclock(u64)
/// CompressedSlots (bincode enum, tag u32 LE; 0=Flate2, 1=Uncompressed):
///   first_slot(u64) num(u64)
///   Flate2:       compressed = serde_bytes -> len(u64) + raw-deflate bytes
///   Uncompressed: BitVec<u8> = bits:Option<Box<[u8]>> then len:u64
///                 = option_tag(u8) [if 1: blocks_len(u64)+bytes] bit_len(u64)
/// Bit k set => peer advertises slot first_slot+k, for k in [0, num)
/// (Agave get_slots, LSB-first within each block: byte=blocks[k/8], set iff
/// (byte >> (k%8))&1). v1 implements Uncompressed ingest; Flate2 is size-walked
/// only (skipped for ingest) — its slots are the older bulk; the freshest tip
/// slots (the repair dead-end case) live in the trailing Uncompressed entry.
pub fn parseEpochSlotsInto(data: []const u8, cs_in: ?*ClusterSlots) ?usize {
    @setRuntimeSafety(false);
    // PERF GATE (2026-06-16): the EpochSlots→ClusterSlots ingest (added 7c8621c
    // 2026-06-14) is a SLOT-AWARE-REPAIR optimization, NOT consensus. Post-restart
    // the cluster floods EpochSlots; insertMany then burns ~24% CPU AND holds
    // cluster_slots.mutex over whole CompressedSlots batches, contending with the
    // repair path (lookupPeers) → replay starved → fall-behind → delinquent
    // (profiled: gossip.walkEpochSlots→ClusterSlots.insertMany dominant). Before
    // 7c8621c Vexor DISCARDED EpochSlots and ran fine for months. Default OFF =
    // that proven baseline: still SIZE-WALK (return value keeps the packet walker
    // in sync — load-bearing) but skip the insert. VEX_EPOCHSLOTS_INGEST=1 restores
    // the ingest once insertMany is made cheap / lock-chunked + pinning rebalanced.
    const cs = if (epochSlotsIngestEnabled()) cs_in else null;
    // MAX_SLOTS_PER_ENTRY = 2048*8 (epoch_slots.rs:15). Bound `num` and the
    // bit-scan so a hostile entry cannot OOB-read or spin.
    const MAX_SLOTS_PER_ENTRY: u64 = 2048 * 8;
    const MAX_SLOT: u64 = 1_000_000_000_000_000; // epoch_slots.rs MAX_SLOT
    const MAX_COMPRESSED_VEC: u64 = 64; // sane cap on # CompressedSlots entries
    const MAX_BLOB: u64 = 64 * 1024; // cap on any length-prefixed byte blob

    var off: usize = 64; // skip signature
    // tag (u32) — caller already read it == 5; re-skip for a self-contained walk.
    if (off + 4 > data.len) return null;
    off += 4;
    // EpochSlotsIndex (u8) — tuple variant CrdsData::EpochSlots(EpochSlotsIndex, _)
    if (off + 1 > data.len) return null;
    off += 1;
    // from: Pubkey (32)
    if (off + 32 > data.len) return null;
    var from: Pubkey = undefined;
    @memcpy(&from, data[off..][0..32]);
    off += 32;
    // slots: Vec<CompressedSlots> — len(u64)
    if (off + 8 > data.len) return null;
    const vec_len = std.mem.readInt(u64, data[off..][0..8], .little);
    off += 8;
    if (vec_len > MAX_COMPRESSED_VEC) return null;

    // Scratch for one entry's extracted slots (bounded by MAX_SLOTS_PER_ENTRY).
    var slot_buf: [MAX_SLOTS_PER_ENTRY]u64 = undefined;

    var vi: u64 = 0;
    while (vi < vec_len) : (vi += 1) {
        // CompressedSlots enum tag (u32 LE)
        if (off + 4 > data.len) return null;
        const cs_tag = std.mem.readInt(u32, data[off..][0..4], .little);
        off += 4;
        // first_slot (u64), num (u64)
        if (off + 16 > data.len) return null;
        const first_slot = std.mem.readInt(u64, data[off..][0..8], .little);
        const num = std.mem.readInt(u64, data[off + 8 ..][0..8], .little);
        off += 16;

        switch (cs_tag) {
            1 => { // Uncompressed: BitVec<u8>
                // bits: Option<Box<[u8]>> — option tag (u8)
                if (off + 1 > data.len) return null;
                const opt = data[off];
                off += 1;
                var blocks: []const u8 = &[_]u8{};
                if (opt == 1) {
                    if (off + 8 > data.len) return null;
                    const blocks_len = std.mem.readInt(u64, data[off..][0..8], .little);
                    off += 8;
                    if (blocks_len > MAX_BLOB) return null;
                    const bl: usize = @intCast(blocks_len);
                    if (off + bl > data.len) return null;
                    blocks = data[off..][0..bl];
                    off += bl;
                } else if (opt != 0) {
                    return null; // invalid Option tag
                }
                // len: u64 (bit_len) — trailing field
                if (off + 8 > data.len) return null;
                const bit_len = std.mem.readInt(u64, data[off..][0..8], .little);
                off += 8;

                // Ingest (only if requested and bounds sane).
                if (cs) |idx| {
                    uncompressed_entries +|= 1;
                    if (first_slot < MAX_SLOT and num <= MAX_SLOTS_PER_ENTRY) {
                        // Iterate k in [0, min(num, bit_len, blocks.len*8)).
                        const end_by_blocks: u64 = @as(u64, blocks.len) * 8;
                        var end: u64 = num;
                        if (bit_len < end) end = bit_len;
                        if (end_by_blocks < end) end = end_by_blocks;
                        var n: usize = 0;
                        var k: u64 = 0;
                        while (k < end) : (k += 1) {
                            const byte = blocks[@intCast(k >> 3)];
                            if ((byte >> @intCast(k & 7)) & 1 == 1) {
                                if (n < slot_buf.len) {
                                    slot_buf[n] = first_slot + k;
                                    n += 1;
                                }
                            }
                        }
                        idx.insertMany(slot_buf[0..n], from);
                    }
                }
            },
            0 => { // Flate2: compressed = serde_bytes (len(u64) + bytes)
                if (off + 8 > data.len) return null;
                const blob_len = std.mem.readInt(u64, data[off..][0..8], .little);
                off += 8;
                if (blob_len > MAX_BLOB) return null;
                const bl: usize = @intCast(blob_len);
                if (off + bl > data.len) return null;
                off += bl;
                // v1: skip slot extraction for Flate2 (size-walked only).
                if (cs != null) flate2_skipped +|= 1;
            },
            else => return null, // unknown CompressedSlots variant
        }
    }

    // wallclock (u64)
    if (off + 8 > data.len) return null;
    off += 8;

    return if (off <= data.len) off else null;
}

// ─────────────────────────── tests ───────────────────────────

// SLOT-AWARE REPAIR KAT (2026-06-14): the EpochSlots wire bytes below are NOT
// hand-built — they are a verbatim `bincode::serialize(&CrdsData::EpochSlots(7,
// es))` dump from Agave 4.1.0-beta.3, where es = EpochSlots{from: default,
// slots: [Uncompressed(new(2).add([1,10,2]))], wallclock: 12345}. This is the
// only non-circular check of the wire framing AND the LSB-first bit->slot
// mapping: first_slot=1, num=10, blocks=[0x03,0x02] => bits {0,1,9} =>
// slots {1, 2, 10}. We prepend 64 zero bytes for the CrdsValue signature
// (parseEpochSlotsInto skips them) and assert (a) the exact byte size and (b)
// the extracted advertised slots.
const KAT_EPOCHSLOTS_BODY = [_]u8{
    // tag = 5 (u32 LE)
    0x05, 0x00, 0x00, 0x00,
    // EpochSlotsIndex = 7
    0x07,
    // from = Pubkey::default() (32 bytes)
    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,    0,    0,    0,
    0,
    // slots_vec_len = 1 (u64 LE)
       0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00,
    // CompressedSlots tag = 1 (Uncompressed)
    0x01, 0x00, 0x00,
    0x00,
    // first_slot = 1
    0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00,
    // num = 10
    0x0a, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00,
    // BitVec.bits Option tag = 1 (Some)
    0x01,
    // blocks_len = 2
    0x02, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    // blocks = [0x03, 0x02]
    0x03, 0x02,
    // bit_len = 16
    0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // wallclock = 12345 (0x3039)
    0x39, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

test "epoch_slots KAT: agave wire vector -> {1,2,10}, exact size" {
    var buf: [64 + KAT_EPOCHSLOTS_BODY.len]u8 = undefined;
    @memset(buf[0..64], 0); // CrdsValue signature
    @memcpy(buf[64..], &KAT_EPOCHSLOTS_BODY);

    // Pure size walk (matches getCrdsValueSize behavior for tag 5).
    const size = parseEpochSlotsInto(&buf, null) orelse return error.WalkFailed;
    try std.testing.expectEqual(@as(usize, buf.len), size); // exact, no over/under-read

    // Ingest walk -> advertised slots. Force the perf gate ON for the test
    // (default is OFF — see epochSlotsIngestEnabled).
    es_ingest_cache = 1;
    defer es_ingest_cache = -1;
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    cs.setRoot(0);
    const size2 = parseEpochSlotsInto(&buf, &cs) orelse return error.WalkFailed;
    try std.testing.expectEqual(@as(usize, buf.len), size2);

    const from: Pubkey = [_]u8{0} ** 32;
    try std.testing.expect(cs.isAdvertiser(1, from));
    try std.testing.expect(cs.isAdvertiser(2, from));
    try std.testing.expect(cs.isAdvertiser(10, from));
    try std.testing.expect(!cs.isAdvertiser(3, from)); // bit not set
    try std.testing.expect(!cs.isAdvertiser(11, from)); // out of num range
    try std.testing.expectEqual(@as(usize, 3), cs.len());
}

test "epoch_slots walker keeps packet offset in sync (trailing bytes)" {
    var buf: [64 + KAT_EPOCHSLOTS_BODY.len + 16]u8 = undefined;
    @memset(&buf, 0xAB);
    @memset(buf[0..64], 0);
    @memcpy(buf[64..][0..KAT_EPOCHSLOTS_BODY.len], &KAT_EPOCHSLOTS_BODY);
    const size = parseEpochSlotsInto(buf[0 .. 64 + KAT_EPOCHSLOTS_BODY.len], null) orelse return error.WalkFailed;
    try std.testing.expectEqual(@as(usize, 64 + KAT_EPOCHSLOTS_BODY.len), size);
}

test "epoch_slots walker rejects short/hostile input (no panic)" {
    var buf: [64 + KAT_EPOCHSLOTS_BODY.len]u8 = undefined;
    @memset(buf[0..64], 0);
    @memcpy(buf[64..], &KAT_EPOCHSLOTS_BODY);
    // Truncated mid-entry: must return null, never panic / OOB.
    try std.testing.expect(parseEpochSlotsInto(buf[0 .. 64 + 60], null) == null);
    // Oversized vec_len -> reject. slots_vec_len at offset 64+4+1+32 = 101.
    var bad = buf;
    std.mem.writeInt(u64, bad[101..][0..8], 1_000_000, .little);
    try std.testing.expect(parseEpochSlotsInto(&bad, null) == null);
}

test "insert/isAdvertiser/lookup within window" {
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    cs.setRoot(100);
    const a: Pubkey = [_]u8{1} ** 32;
    const b: Pubkey = [_]u8{2} ** 32;
    cs.insert(150, a);
    cs.insert(150, b);
    cs.insert(150, a); // dedup
    try std.testing.expect(cs.isAdvertiser(150, a));
    try std.testing.expect(cs.isAdvertiser(150, b));
    try std.testing.expect(!cs.isAdvertiser(151, a));
    var out: [MAX_PEERS_PER_SLOT][32]u8 = undefined;
    const peers = cs.lookupPeers(150, &out);
    try std.testing.expectEqual(@as(usize, 2), peers.len);
}

test "out-of-window dropped on insert" {
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    cs.setRoot(1000);
    const a: Pubkey = [_]u8{1} ** 32;
    cs.insert(1000, a); // == root -> drop
    cs.insert(999, a); // < root -> drop
    cs.insert(1000 + SLOT_WINDOW + 1, a); // > window -> drop
    cs.insert(1000 + SLOT_WINDOW, a); // == window edge -> keep
    cs.insert(1001, a); // keep
    try std.testing.expect(!cs.isAdvertiser(1000, a));
    try std.testing.expect(!cs.isAdvertiser(999, a));
    try std.testing.expect(cs.isAdvertiser(1001, a));
    try std.testing.expect(cs.isAdvertiser(1000 + SLOT_WINDOW, a));
    try std.testing.expectEqual(@as(usize, 2), cs.len());
}

test "setRoot prunes below and above window" {
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    const a: Pubkey = [_]u8{1} ** 32;
    cs.setRoot(100);
    cs.insert(200, a);
    cs.insert(300, a);
    cs.insert(40_300, a);
    try std.testing.expectEqual(@as(usize, 3), cs.len());
    cs.setRoot(250); // prunes 200 (<=root); keeps 300, 40300
    try std.testing.expect(!cs.isAdvertiser(200, a));
    try std.testing.expect(cs.isAdvertiser(300, a));
    try std.testing.expectEqual(@as(usize, 2), cs.len());
    cs.setRoot(200); // non-increasing -> ignored
    try std.testing.expectEqual(@as(usize, 2), cs.len());
}

test "per-slot advertiser cap" {
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    cs.setRoot(0);
    var i: usize = 0;
    while (i < MAX_PEERS_PER_SLOT + 10) : (i += 1) {
        var pk: Pubkey = [_]u8{0} ** 32;
        std.mem.writeInt(u64, pk[0..8], @intCast(i), .little);
        cs.insert(5, pk);
    }
    var out: [MAX_PEERS_PER_SLOT][32]u8 = undefined;
    const peers = cs.lookupPeers(5, &out);
    try std.testing.expectEqual(@as(usize, MAX_PEERS_PER_SLOT), peers.len);
}

test "insertMany single lock" {
    var cs = ClusterSlots.init(std.testing.allocator);
    defer cs.deinit();
    cs.setRoot(0);
    const a: Pubkey = [_]u8{7} ** 32;
    const slots = [_]u64{ 1, 2, 5, 60_000, 10 }; // 60000 > window -> dropped
    cs.insertMany(&slots, a);
    try std.testing.expect(cs.isAdvertiser(1, a));
    try std.testing.expect(cs.isAdvertiser(2, a));
    try std.testing.expect(cs.isAdvertiser(5, a));
    try std.testing.expect(cs.isAdvertiser(10, a));
    try std.testing.expect(!cs.isAdvertiser(60_000, a));
    try std.testing.expectEqual(@as(usize, 4), cs.len());
}
