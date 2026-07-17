//! VexLedger — a Zig-native, crash-recoverable append-SEGMENT blockstore.
//!
//! Stores raw shred WIRE BYTES verbatim in a series of append-only SEGMENT files
//! (`<ledger_path>/vexledger-<seq>.seg`) and maintains an in-memory index that is
//! rebuilt by replaying the segments on open. This module is intentionally
//! `std`-ONLY: it has no dependency on `core` / vex_store and uses plain
//! `u64`/`u32` so it can be unit-tested in isolation.
//!
//! Scope = storage + in-mem index + SlotMeta + read-back + index-rebuild-from-
//! segments + ROLLING SEGMENTS (Phase 4a) so the ledger is prunable by O(1)
//! `unlink()` of whole sealed segments (Phase 4b). There is deliberately NO mmap
//! and NO sidecar `.idx` yet — recovery rebuilds the index by a full segment scan
//! (correct; a `.idx` fast-path is a deferred Tier-1 perf option).
//!
//! ON-DISK FORMAT (each segment = records concatenated, identical layout):
//!
//!   kind:    u8           // 0 = data shred, 1 = slot meta, 2 = root marker
//!   slot:    u64 (LE)
//!   aux:     u32 (LE)     // data shred: shred index; meta/root: 0
//!   len:     u32 (LE)     // payload byte length
//!   payload: [len]u8
//!
//! Header is 17 bytes (1 + 8 + 4 + 4). Records are appended sequentially to the
//! ACTIVE segment; each segment tracks its own `write_offset` (end of its log).
//!
//! SEGMENTS: a fresh ledger writes to `vexledger-0000000001.seg`. When the active
//! segment reaches `target_segment_bytes` (checked at a `finishSlot` boundary so a
//! slot stays mostly whole-in-one-segment), it is sealed (left read-only in place)
//! and a new active segment `vexledger-<seq+1>.seg` is opened. Pruning unlinks a
//! whole sealed segment once every slot it holds is below the keep-floor.
//!
//! LEGACY: an existing single-file `vexledger.log` (the pre-segment format) is read
//! as the oldest segment (seq 0, read-only, never appended/truncated) so artifacts
//! written by the original blockstore still replay without conversion.
//!
//! RECOVERY: scan every segment (legacy first, then `.seg` by ascending seq),
//! replaying each complete record to rebuild the index/meta/roots. A short/torn
//! final record in the ACTIVE segment (a crash mid-write) is treated as end-of-log
//! and truncated; sealed/legacy segments are scanned read-only (a torn tail there
//! just bounds the scan, never mutates the file).

const std = @import("std");
pub const agave_wire = @import("agave_wire.zig");
pub const agave_proto = @import("agave_proto.zig");
pub const agave_json = @import("agave_json.zig"); // bincode-TransactionError → serde_json err render (reachable as vex_ledger_mod.agave_json from rpc_methods)
pub const agave_tx_json = @import("agave_tx_json.zig"); // tx WIRE → rc.1 "json" transaction render (getBlock/getTransaction)
pub const agave_meta_json = @import("agave_meta_json.zig"); // DecodedTransactionStatusMeta → rc.1 meta JSON
pub const divergence_alarm = @import("divergence_alarm.zig"); // P5 MOAT #2 M1: the pure 4-input classify() seam
pub const divergence_alarm_rt = @import("divergence_alarm_rt.zig"); // P5 MOAT #2 M2: live SPSC ring + alarm thread + oracle (VEX_DIVERGE_ALARM)

/// On-disk record header size: kind(1) + slot(8) + aux(4) + len(4).
const HEADER_LEN: usize = 17;

/// Record kinds (the `kind` byte).
const KIND_SHRED: u8 = 0; // data shred (aux = shred index)
const KIND_META: u8 = 1; // SlotMeta (aux = 0)
const KIND_ROOT: u8 = 2; // root marker (aux = 0)
const KIND_CODE: u8 = 3; // coding shred (aux = shred index) — @prov:ledger.column-families (code_shred)
const KIND_ERASURE: u8 = 4; // erasure_meta (aux = fec_set_index; payload = byte-exact wire)
const KIND_MERKLE: u8 = 5; // merkle_root_meta (aux = fec_set_index; payload = byte-exact wire)
// ── RPC/execution-product CFs. @prov:ledger.column-families
// (TransactionStatus / AddressSignatures / Rewards / Blocktime / BlockHeight).
// For sig/pubkey-keyed records the key cannot fit the u32 `aux`, so the key
// bytes are framed in the PAYLOAD PREFIX (slot still lives in the header);
// recovery parses them back.
const KIND_TX_STATUS: u8 = 6; // transaction_status (payload = sig[64] ++ protobuf_bytes; aux=0)
const KIND_MEMO: u8 = 7; // transaction_memos (payload = sig[64] ++ memo_utf8; aux=0)
const KIND_ADDR_SIG: u8 = 8; // address_signatures (payload = pk[32]++tx_index(u32)++sig[64]++writeable(1); aux=tx_index)
const KIND_REWARDS: u8 = 9; // rewards (payload = protobuf_bytes; slot key in header)
const KIND_BLOCKTIME: u8 = 10; // blocktime (payload = i64 LE; slot key in header)
const KIND_BLOCKHEIGHT: u8 = 11; // block_height (payload = u64 LE; slot key in header)
// P5 #1 per-slot FLIGHT RECORDER (Vexor-native forensic, NOT an Agave CF): the
// bank_hash INPUT decomposition co-stored next to the shreds so any future
// divergence carrier is diagnosable from the ledger alone. Payload = the fixed
// 2152-byte FlightRecord (slot key in header). Opt-in (the freeze tap is env-gated
// VEX_LEDGER_FLIGHT in fix105; the module API is comptime-dead on default build).
const KIND_FLIGHT: u8 = 12;
// @prov:ledger.column-families (bank_hashes, byte-exact interop): payload =
// the 37-byte wincode FrozenHashVersioned::Current value (agave_wire.encodeFrozenHash;
// slot key in header). Closes the P4-deferred bank_hashes gap → ledger-tool interop. Stores
// the FROZEN bank_hash + is_duplicate_confirmed alongside the native KIND_FLIGHT.
const KIND_BANK_HASH: u8 = 13;
// Vexor-native SLOT→SIGNATURE secondary index (NOT an Agave CF): payload = sig[64];
// slot in the header; aux carries tx_index (the tx's position in the block). Serves
// getBlock's per-slot transaction enumeration (the (sig,slot)-keyed tx_status map can't
// list a slot's sigs in block order). Populated once per tx at putSlotSignature time,
// INDEPENDENT of the deferred tx-capture meta. Rebuilt on recovery; seq-precise pruned.
const KIND_SLOT_SIG: u8 = 14;
// Vexor-native TRANSACTION WIRE store (NOT an Agave CF; option (a) — indexed sig→wire, NOT shred
// re-derivation): payload = sig[64] ++ raw-tx-wire; slot in header; aux=0. Serves getTransaction/
// getBlock's `transaction` field (the message/instructions/recentBlockhash live ONLY in the wire, not
// in the meta). Populated once per tx alongside putTransactionStatus, gated by VEX_LEDGER_CONTENT.
// Decoupled from sig_index (tx_status owns that point lookup); population stores status+wire together.
const KIND_TX_WIRE: u8 = 15;
// Vexor-native SLOT BLOCKHASH store (NOT an Agave CF): payload = blockhash[32] (the slot's PoH
// last_blockhash = bank.poh_hash); slot in header; aux=0. Serves getBlock's blockhash/previousBlockhash
// (PoH, NOT in the tx wire). Populated from bank at freeze (VEX_LEDGER_CONTENT). Slot-keyed, last-wins.
const KIND_BLOCKHASH: u8 = 16;

/// Sentinels used in the fixed-layout SlotMeta serialization to encode the
/// `?u64` parent_slot / `?u32` last_index "None" states on disk.
const PARENT_NONE: u64 = std.math.maxInt(u64);
const LAST_INDEX_NONE: u32 = std.math.maxInt(u32);

/// Legacy single-file log name, read as the oldest segment (seq 0, read-only).
const LEGACY_LOG_FILENAME = "vexledger.log";

/// Default roll threshold: seal the active segment once it reaches this size.
/// 256 MiB ≈ a few hundred slots per segment,
/// fine-grained enough for whole-segment eviction. Overridable per instance.
pub const DEFAULT_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;

/// Identifies a single data shred by (slot, index).
pub const ShredKey = struct {
    slot: u64,
    index: u32,
};

/// Identifies an erasure_meta / merkle_root_meta record by (slot, fec_set_index).
pub const FecKey = struct {
    slot: u64,
    fec_set_index: u32,
};

/// An erasure_meta value + its backing segment seq (for prune-accurate eviction).
const StoredErasure = struct { meta: agave_wire.ErasureMeta, seq: u32 };
/// A merkle_root_meta value + its backing segment seq.
const StoredMerkle = struct { meta: agave_wire.MerkleRootMeta, seq: u32 };

/// (signature, slot) key for the sig-keyed CFs (transaction_status, memos). The
/// full 64-byte sig + slot can't fit the u32 record `aux`, so the sig is framed
/// in the payload prefix; this is the in-memory index key.
pub const SigSlotKey = struct { sig: [64]u8, slot: u64 };
/// (pubkey, slot, tx_index, sig) key for the address_signatures CF.
pub const AddrSigKey = struct { pubkey: [32]u8, slot: u64, tx_index: u32, sig: [64]u8 };

/// An OWNED opaque byte value (protobuf / utf8 memo) + its backing segment seq.
/// `bytes` is heap-owned: dup'd on put, freed on overwrite / prune / deinit.
const StoredBytes = struct { bytes: []u8, seq: u32 };
/// A blocktime value (bare i64) + its backing segment seq.
const StoredI64 = struct { value: i64, seq: u32 };
/// A block_height value (bare u64) + its backing segment seq.
const StoredU64 = struct { value: u64, seq: u32 };
/// A slot blockhash (32 bytes) + its backing segment seq.
const StoredBlockhash = struct { hash: [32]u8, seq: u32 };
/// An address_signature value (writeable bool) + its backing segment seq.
const StoredAddrSig = struct { writeable: bool, seq: u32 };
/// One entry in the secondary by-pubkey enumeration index (for
/// getSignaturesForAddress). Mirrors an addr_sigs record grouped under its
/// pubkey; `seq` is the backing segment (for seq-precise prune).
const AddrSigEntry = struct { slot: u64, tx_index: u32, sig: [64]u8, seq: u32 };

/// One `getSignaturesForAddress` result row (the blockstore-sourced fields). The
/// RPC handler joins `err` (tx_status), `memo` (memos), `blockTime` (blocktime)
/// and computes `confirmationStatus` — those are separate CF reads, per rc.1.
pub const SignatureInfo = struct { signature: [64]u8, slot: u64, tx_index: u32 };

/// (slot, tx_index) key for the slot→signature index dedup-guard map. tx_index is
/// unique within a slot (a tx's block position), so this alone keys a tx.
const SlotSigKey = struct { slot: u64, tx_index: u32 };
/// One entry in the secondary by-slot enumeration index (for getBlock). `seq` is the
/// backing segment (for seq-precise prune, lockstep with the dedup map).
const SlotSigEntry = struct { tx_index: u32, sig: [64]u8, seq: u32 };
/// One `getSlotSignatures` result row: a tx's block position + its signature, returned
/// ascending by tx_index (block order) for getBlock's transaction list.
pub const SlotSigInfo = struct { tx_index: u32, signature: [64]u8 };
/// A FlightRecord (fixed 2152B, no heap) + its backing segment seq.
const StoredFlight = struct { rec: FlightRecord, seq: u32 };
/// A decoded bank_hashes CF value (frozen_hash + dup-confirmed) + backing seq.
const StoredBankHash = struct { frozen_hash: [32]u8, is_duplicate_confirmed: bool, seq: u32 };

/// P5 #1 per-slot FLIGHT RECORD — the bank_hash INPUT decomposition read off the
/// FROZEN bank at freeze time (the [BANK-FROZEN] emit site). A Vexor-NATIVE
/// forensic record (not an Agave interop CF) so the layout is ours: a fixed,
/// little-endian, 2152-byte payload (no length prefixes, no None states). Stored
/// BY VALUE (no allocation). `accounts_lt_hash` is the FULL 2048B AccountsLtHash
/// (@prov:ledger.flight-record-lthash), NOT the 8-byte checksum.
pub const FlightRecord = struct {
    bank_hash: [32]u8 = [_]u8{0} ** 32,
    parent_hash: [32]u8 = [_]u8{0} ** 32,
    signature_count: u64 = 0,
    poh_hash: [32]u8 = [_]u8{0} ** 32, // the slot's blockhash (PoH last_blockhash input)
    accounts_lt_hash: [2048]u8 = [_]u8{0} ** 2048,

    /// On-disk payload size: 32 + 32 + 8 + 32 + 2048 = 2152 bytes.
    pub const PAYLOAD_LEN: usize = 32 + 32 + 8 + 32 + 2048;

    /// Serialize to the fixed LE payload (writes into `out`, exactly PAYLOAD_LEN).
    pub fn encode(self: FlightRecord, out: *[PAYLOAD_LEN]u8) void {
        @memcpy(out[0..32], &self.bank_hash);
        @memcpy(out[32..64], &self.parent_hash);
        std.mem.writeInt(u64, out[64..72], self.signature_count, .little);
        @memcpy(out[72..104], &self.poh_hash);
        @memcpy(out[104..2152], &self.accounts_lt_hash);
    }

    /// Decode from a fixed LE payload (caller guarantees `buf.len == PAYLOAD_LEN`).
    pub fn decode(buf: []const u8) FlightRecord {
        var r = FlightRecord{};
        @memcpy(&r.bank_hash, buf[0..32]);
        @memcpy(&r.parent_hash, buf[32..64]);
        r.signature_count = std.mem.readInt(u64, buf[64..72], .little);
        @memcpy(&r.poh_hash, buf[72..104]);
        @memcpy(&r.accounts_lt_hash, buf[104..2152]);
        return r;
    }
};

/// Location of a shred payload within a specific segment file.
pub const Loc = struct {
    /// Owning segment's stable sequence id (`seg_by_seq` key). Legacy log = 0.
    seq: u32,
    /// Byte offset of the PAYLOAD (not the header) within that segment.
    offset: u64,
    /// Payload length in bytes.
    len: u32,
};

/// @prov:ledger.connected-flags — bitflags for `connected_flags`.
pub const CONNECTED_FLAG: u8 = 0b0000_0001; // this slot's chain reaches a root
pub const PARENT_CONNECTED_FLAG: u8 = 0b1000_0000; // 0x80, NOT 0x02

/// Per-slot metadata. @prov:ledger.slot-meta-wire (encoded
/// via `agave_wire.SlotMetaV3`). The two owned slices (`completed_data_indexes`,
/// `next_slots`) are owned by the `slot_meta` map: deep-copied on `finishSlot`
/// (and recovery), freed when overwritten, and freed on `deinit`. Callers passing
/// a `SlotMeta` into `finishSlot` retain ownership of their own slices (copied).
pub const SlotMeta = struct {
    /// Parent slot; `null` == wire `None` (OptionCompat bare-u64 None=MAX). @prov:ledger.slot-meta-wire
    parent_slot: ?u64 = null,
    /// Highest data index seen + 1.
    received: u32 = 0,
    /// Highest contiguous index+1 starting from 0.
    consumed: u32 = 0,
    /// Last (terminal) data index of the slot; `null` == not-yet-known.
    last_index: ?u32 = null,
    /// @prov:ledger.connected-flags — bitfield (CONNECTED | PARENT_CONNECTED). Replaces the
    /// old `is_connected: bool` (a bool can't hold 2 bits). The CHAINED value is
    /// set by the persist tap per the canonical ConnectedFlags algorithm.
    connected_flags: u8 = 0,
    /// Wall-clock timestamp (ms) of the first shred received for this slot.
    first_shred_timestamp: u64 = 0,
    /// Sorted-ascending list of completed FEC-set data indexes.
    completed_data_indexes: []const u32 = &.{},
    /// Child slots that chain off this one (SlotMetaV3 `next_slots`). Owned slice.
    next_slots: []const u64 = &.{},
    /// SlotMetaV3 `parent_block_id` (Alpenglow; 0 until block-id repair is wired).
    parent_block_id: [32]u8 = [_]u8{0} ** 32,
    /// SlotMetaV3 `replay_fec_set_index`.
    replay_fec_set_index: u32 = 0,
};

/// FINISH ring-message codec — the dedicated-ledger-tile contract.
///
/// When ledger I/O is moved OFF the consensus hot path onto a dedicated tile,
/// the completion (PRODUCER) side derives the SlotMeta (it has the shred flags)
/// and packs it into a FIXED inline ring buffer; the ledger tile (CONSUMER)
/// decodes it and calls `finishSlot`. Both sides share THIS codec so the wire
/// shape can never drift between producer and consumer (one implementation).
///
/// This is an INTERNAL ring message, NOT the stored on-disk record: it is
/// compact (no SlotMetaV3 4197B framing), never persisted, never interop'd. The
/// stored record is still produced byte-exactly by `finishSlot` from the
/// decoded SlotMeta. `next_slots` is NOT carried (empty at completion time —
/// chaining happens later, off the ring); every other SlotMeta field is.
///
/// Fixed-offset layout (all LE):
///   [0..8)   parent_slot           u64   (PARENT_NONE = None)
///   [8..12)  received              u32
///   [12..16) consumed              u32
///   [16..20) last_index            u32   (LAST_INDEX_NONE = None)
///   [20..24) replay_fec_set_index  u32
///   [24]     connected_flags       u8
///   [25..33) first_shred_timestamp u64
///   [33..65) parent_block_id       [32]u8
///   [65..69) num_completed         u32
///   [69..)   completed_data_indexes[num_completed] u32
pub const FinishBlob = struct {
    /// Fixed prefix length (everything before the variable completed[] list).
    pub const HEADER_LEN: usize = 69; // (ref as FinishBlob.HEADER_LEN internally)

    /// Exact encoded byte length for `m`. The producer calls this at ENQUEUE to
    /// size/assert the ring buffer (the tile-spec §B decision: assert at
    /// enqueue, drop+log if a meta would exceed the inline buf rather than
    /// corrupt). Bounded by FinishBlob.HEADER_LEN + 4·(num data shreds).
    pub fn encodedLen(m: SlotMeta) usize {
        return FinishBlob.HEADER_LEN + m.completed_data_indexes.len * 4;
    }

    /// Encode `m` into `buf` (the ring slot's inline buffer — NO heap). Returns
    /// the written prefix `buf[0..encodedLen(m)]`. Errors `BufferTooSmall` if
    /// the blob would not fit (the producer then drops+logs rather than write a
    /// truncated/corrupt FINISH).
    pub fn encode(buf: []u8, m: SlotMeta) error{BufferTooSmall}![]u8 {
        const need = encodedLen(m);
        if (buf.len < need) return error.BufferTooSmall;
        std.mem.writeInt(u64, buf[0..8], m.parent_slot orelse PARENT_NONE, .little);
        std.mem.writeInt(u32, buf[8..12], m.received, .little);
        std.mem.writeInt(u32, buf[12..16], m.consumed, .little);
        std.mem.writeInt(u32, buf[16..20], m.last_index orelse LAST_INDEX_NONE, .little);
        std.mem.writeInt(u32, buf[20..24], m.replay_fec_set_index, .little);
        buf[24] = m.connected_flags;
        std.mem.writeInt(u64, buf[25..33], m.first_shred_timestamp, .little);
        @memcpy(buf[33..65], &m.parent_block_id);
        std.mem.writeInt(u32, buf[65..69], @intCast(m.completed_data_indexes.len), .little);
        var o: usize = FinishBlob.HEADER_LEN;
        for (m.completed_data_indexes) |ci| {
            std.mem.writeInt(u32, buf[o..][0..4], ci, .little);
            o += 4;
        }
        return buf[0..need];
    }

    /// Decode a FINISH blob into an OWNED SlotMeta. The returned
    /// `completed_data_indexes` is allocated with `allocator` and owned by the
    /// caller; `finishSlot` deep-copies it (the caller frees its own copy).
    /// Read-strictness: a `num_completed` that would overrun `buf` is rejected
    /// (`Truncated`) BEFORE allocating, never over-read.
    pub fn decode(allocator: std.mem.Allocator, buf: []const u8) !SlotMeta {
        if (buf.len < FinishBlob.HEADER_LEN) return error.Truncated;
        const parent_raw = std.mem.readInt(u64, buf[0..8], .little);
        const received = std.mem.readInt(u32, buf[8..12], .little);
        const consumed = std.mem.readInt(u32, buf[12..16], .little);
        const last_raw = std.mem.readInt(u32, buf[16..20], .little);
        const replay_fec = std.mem.readInt(u32, buf[20..24], .little);
        const cflags = buf[24];
        const first_ts = std.mem.readInt(u64, buf[25..33], .little);
        var pbid: [32]u8 = undefined;
        @memcpy(&pbid, buf[33..65]);
        const num = std.mem.readInt(u32, buf[65..69], .little);
        // read-strictness: each entry is 4 bytes; reject an over-long count
        // before allocating (a corrupt/truncated ring slot must not over-read).
        if (num > (buf.len - FinishBlob.HEADER_LEN) / 4) return error.Truncated;
        const completed = try allocator.alloc(u32, num);
        errdefer allocator.free(completed);
        var o: usize = FinishBlob.HEADER_LEN;
        for (completed) |*ci| {
            ci.* = std.mem.readInt(u32, buf[o..][0..4], .little);
            o += 4;
        }
        return SlotMeta{
            .parent_slot = if (parent_raw == PARENT_NONE) null else parent_raw,
            .received = received,
            .consumed = consumed,
            .last_index = if (last_raw == LAST_INDEX_NONE) null else last_raw,
            .replay_fec_set_index = replay_fec,
            .connected_flags = cflags,
            .first_shred_timestamp = first_ts,
            .parent_block_id = pbid,
            .completed_data_indexes = completed,
            .next_slots = &.{},
        };
    }
};

/// Error set surfaced by VexLedger operations beyond the std fs/alloc errors.
pub const VexLedgerError = error{
    /// A record header declared a payload length that runs past EOF in a way
    /// that is NOT a recoverable torn tail (only used defensively; recovery
    /// itself treats short tails as end-of-log).
    CorruptRecord,
    /// Internal invariant: an index entry referenced a segment seq that is not
    /// in `seg_by_seq` (should be impossible — pruning drops index entries for a
    /// segment before/with unlinking it).
    DanglingSegmentRef,
};

/// Reclamation result returned by the prune entry points.
pub const PruneStats = struct {
    /// Whole sealed segments unlinked from disk.
    segments_unlinked: u32 = 0,
    /// Bytes reclaimed (sum of unlinked segments' on-disk sizes).
    bytes_freed: u64 = 0,
    /// Data-shred-index entries dropped (their backing segment was unlinked).
    shreds_dropped: u64 = 0,
    /// Coding-shred-index entries dropped.
    codes_dropped: u64 = 0,
    /// SlotMeta entries dropped.
    metas_dropped: u64 = 0,
    /// Root entries dropped.
    roots_dropped: u64 = 0,
    /// transaction_status entries dropped (G6 lockstep, sig-keyed).
    tx_status_dropped: u64 = 0,
    /// transaction_memos entries dropped (G6 lockstep, sig-keyed).
    memos_dropped: u64 = 0,
    /// address_signatures entries dropped (G6 lockstep, pubkey-keyed).
    addr_sigs_dropped: u64 = 0,
    /// rewards entries dropped (slot-keyed).
    rewards_dropped: u64 = 0,
    /// blocktime entries dropped (slot-keyed).
    blocktime_dropped: u64 = 0,
    /// block_height entries dropped (slot-keyed).
    block_height_dropped: u64 = 0,
    /// blockhash records dropped (slot-keyed).
    blockhash_dropped: u64 = 0,
    /// flight (P5 #1) records dropped (slot-keyed).
    flight_dropped: u64 = 0,
    /// bank_hashes records dropped (slot-keyed).
    bank_hashes_dropped: u64 = 0,
    /// slot→sig index records dropped (slot/tx_index-keyed).
    slot_sigs_dropped: u64 = 0,
    /// transaction-wire records dropped ((sig,slot)-keyed, free owned bytes).
    tx_wire_dropped: u64 = 0,
    /// Lowest slot still backed by a surviving segment after the prune (null if
    /// the ledger is now empty). Below this, the ledger guarantees nothing.
    lowest_kept: ?u64 = null,
};

/// One append-only segment file + its in-memory bookkeeping.
const Segment = struct {
    /// Stable sequence id (also the `seg_by_seq` key). Legacy log = 0.
    seq: u32,
    /// True for the legacy `vexledger.log` (opened read-only, never appended).
    is_legacy: bool,
    /// The segment file (read+write for `.seg`, read-only for legacy).
    file: std.fs.File,
    /// End-of-log byte offset within THIS segment; next append starts here.
    write_offset: u64 = 0,
    /// Lowest slot of any record stored in this segment (null if empty).
    min_slot: ?u64 = null,
    /// Highest slot of any record stored in this segment (null if empty).
    /// Pruning unlinks a segment iff `max_slot < keep_floor` — i.e. EVERY record
    /// it holds is below the floor (interleaving-safe: a slot's shreds landing in
    /// an older segment keep that segment alive until the floor passes them).
    max_slot: ?u64 = null,

    /// Record that a record for `slot` was stored here (updates min/max_slot).
    fn observeSlot(self: *Segment, slot: u64) void {
        if (self.min_slot == null or slot < self.min_slot.?) self.min_slot = slot;
        if (self.max_slot == null or slot > self.max_slot.?) self.max_slot = slot;
    }
};

/// Format a segment filename into `buf`. Legacy returns the fixed log name.
fn segFilename(seq: u32, is_legacy: bool, buf: []u8) []const u8 {
    if (is_legacy) return LEGACY_LOG_FILENAME;
    return std.fmt.bufPrint(buf, "vexledger-{d:0>10}.seg", .{seq}) catch unreachable;
}

/// Parse `vexledger-<seq>.seg` → seq, or null if `name` isn't a segment file.
fn parseSegSeq(name: []const u8) ?u32 {
    const prefix = "vexledger-";
    const suffix = ".seg";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    if (!std.mem.endsWith(u8, name, suffix)) return null;
    const mid = name[prefix.len .. name.len - suffix.len];
    return std.fmt.parseInt(u32, mid, 10) catch null;
}

pub const VexLedger = struct {
    allocator: std.mem.Allocator,
    /// Owned duplicate of the ledger directory path (freed on deinit).
    ledger_path: []const u8,

    /// All live segments by stable seq id (each value heap-allocated, owned here).
    seg_by_seq: std.AutoHashMap(u32, *Segment),
    /// Seq of the ACTIVE (appendable) segment. Always a non-legacy `.seg`.
    active_seq: u32,
    /// Seq to assign to the NEXT new segment (monotonic; never reused).
    next_seq: u32,
    /// Seal the active segment once its `write_offset` reaches this (public so a
    /// caller/test can tune it; defaults to DEFAULT_SEGMENT_BYTES on init).
    target_segment_bytes: u64,
    /// fsync cadence (VEX_LEDGER_FSYNC_EVERY). 1 (default) = fsync every completed
    /// slot (the durable-offline-replay guarantee). N>1 = batch the per-slot fsync
    /// to once per N slots for throughput; the <N-slot un-flushed tail is kernel-
    /// resident (survives signal-kill) + network-recoverable on hard power loss.
    /// A segment roll always syncs, so sealed segments stay durable regardless.
    fsync_every: u64 = 1,
    slots_since_fsync: u64 = 0,

    /// (slot, index) -> payload location (segment seq + offset + len).
    /// O(1) point lookup (getShred). NOTE: shred `index` is u32 because the
    /// Solana wire shred index IS u32 (header bytes 73..77) and never exceeds it;
    /// @prov:ledger.shred-index-width — a wider key width exists only to make
    /// RocksDB range-scans BE-ordered — VexLedger gets ordered enumeration from the
    /// `slot_shreds` per-slot lists below, so the wider width would be cargo-cult.
    shred_index: std.AutoHashMap(ShredKey, Loc),
    /// slot -> the data-shred indices present for that slot (dup-free; sorted on
    /// read). Maintained incrementally so getSlotShredIndices / lowest / highest
    /// are O(#slots-or-k), NOT an O(total-shreds) scan of `shred_index` (G4 — the
    /// ordered-enumeration the canonical contract needs for repair-serve / iterators).
    slot_shreds: std.AutoHashMap(u64, std.ArrayListUnmanaged(u32)),

    /// (slot, index) -> coding shred payload location. @prov:ledger.column-families (code_shred)
    /// Stored verbatim like data shreds; repair-serve + a complete drop-in. Vexor
    /// does FEC RECOVERY upstream in fec_resolver.zig, so the ledger is STORE-ONLY.
    code_index: std.AutoHashMap(ShredKey, Loc),
    /// slot -> coding-shred indices present. @prov:ledger.column-families (index, `coding` half)
    /// Together with `slot_shreds` (the `data` half) this IS the Index —
    /// derived + rebuilt on recovery, so VexLedger persists no redundant index CF.
    slot_codes: std.AutoHashMap(u64, std.ArrayListUnmanaged(u32)),
    /// slot -> SlotMeta (owns completed_data_indexes slices).
    slot_meta: std.AutoHashMap(u64, SlotMeta),
    /// slot -> backing segment seq of that slot's LATEST meta record. Parallel to
    /// `slot_meta`; in-memory only (not serialized). Pruning uses it to drop a
    /// meta entry exactly when its backing segment is unlinked (a meta record can
    /// live in a different segment than the slot's shreds — written at finishSlot).
    meta_seq: std.AutoHashMap(u64, u32),
    /// rooted slot -> backing segment seq of that slot's LATEST root record.
    /// (A root for slot S is written ~32 slots later than S's shreds, so it often
    /// lands in a later segment — seq-precise tracking keeps prune disk-accurate.)
    roots: std.AutoHashMap(u64, u32),
    /// (slot, fec_set_index) -> ErasureMeta + backing seq. @prov:ledger.column-families (erasure_meta, byte-exact wire)
    /// STORE-ONLY — Vexor's fec_resolver does recovery.
    erasure_meta: std.AutoHashMap(FecKey, StoredErasure),
    /// (slot, fec_set_index) -> MerkleRootMeta + backing seq. @prov:ledger.column-families
    /// (merkle_root_meta, byte-exact wire; dup-shred detection input).
    merkle_meta: std.AutoHashMap(FecKey, StoredMerkle),

    /// (sig, slot) -> protobuf TransactionStatusMeta bytes. @prov:ledger.column-families
    /// (transaction_status). OWNED bytes. Sig-keyed: NOT slot-prefixed, so it
    /// can't be range-deleted by slot — evicted in lockstep with its segment (G6).
    tx_status: std.AutoHashMap(SigSlotKey, StoredBytes),
    /// sig -> latest slot a status was recorded for. @prov:ledger.column-families
    /// (TransactionStatusIndex point lookup `slotForSignature`). Latest-wins on put.
    sig_index: std.AutoHashMap([64]u8, u64),
    /// (sig, slot) -> raw memo utf8 bytes. @prov:ledger.column-families (transaction_memos). OWNED.
    memos: std.AutoHashMap(SigSlotKey, StoredBytes),
    /// (pubkey, slot, tx_index, sig) -> writeable flag. @prov:ledger.column-families
    /// (address_signatures). Pubkey-keyed → G6 lockstep eviction with its segment.
    addr_sigs: std.AutoHashMap(AddrSigKey, StoredAddrSig),
    /// Secondary ENUMERATION index: pubkey -> unordered list of its address-sig
    /// entries (sorted per query). Serves getSignaturesForAddress (the unordered
    /// addr_sigs map can't enumerate a pubkey's sigs newest-first). Rebuilt on
    /// recovery; seq-precise pruned in lockstep with addr_sigs.
    addr_sig_index: std.AutoHashMap([32]u8, std.ArrayListUnmanaged(AddrSigEntry)),
    /// slot -> protobuf Rewards bytes. @prov:ledger.column-families (rewards). OWNED bytes.
    rewards: std.AutoHashMap(u64, StoredBytes),
    /// slot -> block unix timestamp i64. @prov:ledger.column-families (blocktime)
    blocktime: std.AutoHashMap(u64, StoredI64),
    /// slot -> block height u64. @prov:ledger.column-families (block_height)
    block_height: std.AutoHashMap(u64, StoredU64),
    /// slot -> PoH blockhash (Vexor-native KIND_BLOCKHASH; getBlock blockhash/previousBlockhash).
    blockhash: std.AutoHashMap(u64, StoredBlockhash),
    /// slot -> FlightRecord (P5 #1 Vexor-native bank_hash-input forensic record).
    flight: std.AutoHashMap(u64, StoredFlight),
    /// slot -> FrozenHashVersioned value. @prov:ledger.column-families (bank_hashes, byte-exact)
    bank_hashes: std.AutoHashMap(u64, StoredBankHash),
    /// (slot, tx_index) -> backing seq. Dedup-guard for the slot→sig index (insert
    /// into slot_sig_index only on a NEW key). Slot-keyed → G6 lockstep eviction.
    slot_sigs: std.AutoHashMap(SlotSigKey, u32),
    /// Secondary ENUMERATION index: slot -> unordered list of its (tx_index, sig)
    /// entries (sorted ascending per query). Serves getBlock's per-slot tx list.
    /// Rebuilt on recovery; seq-precise pruned in lockstep with slot_sigs.
    slot_sig_index: std.AutoHashMap(u64, std.ArrayListUnmanaged(SlotSigEntry)),
    /// (sig, slot) -> OWNED raw transaction wire bytes (Vexor-native KIND_TX_WIRE). Feeds
    /// getTransaction/getBlock's `transaction` field. Decoupled from sig_index.
    tx_wire: std.AutoHashMap(SigSlotKey, StoredBytes),

    /// Guards all in-mem state + the segment files. SHARED for reads (get*/meta/
    /// isRoot/lowest+highestSlot), EXCLUSIVE for writes (putShred/finishSlot/
    /// setRoot/prune). Required because the live persist tap runs on the verify-
    /// worker threads + the repair path, and repair-serve reads concurrently.
    /// Reads use positional pread (no shared file cursor); the cursor (seekTo) is
    /// only touched under the exclusive write lock, so pread-readers never race it.
    /// `recover()` runs single-threaded during init (before the handle is shared),
    /// so it is intentionally unlocked.
    lock: std.Thread.RwLock = .{},

    /// Create/open a ledger at `ledger_path`. Creates the directory if needed,
    /// opens (or creates) the segment files WITHOUT truncating, and — if any
    /// segment already has content — replays it to rebuild the in-mem index.
    /// Returns a heap-allocated VexLedger; free with `deinit`.
    pub fn init(allocator: std.mem.Allocator, ledger_path: []const u8) !*VexLedger {
        // Ensure the ledger directory exists. makePath is idempotent.
        try std.fs.cwd().makePath(ledger_path);

        const self = try allocator.create(VexLedger);
        errdefer allocator.destroy(self);

        const path_dup = try allocator.dupe(u8, ledger_path);
        errdefer allocator.free(path_dup);

        // fsync cadence: VEX_LEDGER_FSYNC_EVERY=N (default 1 = fsync every slot).
        const fsync_every: u64 = blk: {
            const v = std.posix.getenv("VEX_LEDGER_FSYNC_EVERY") orelse break :blk 1;
            const n = std.fmt.parseInt(u64, v, 10) catch break :blk 1;
            break :blk if (n == 0) 1 else n;
        };

        self.* = .{
            .allocator = allocator,
            .ledger_path = path_dup,
            .seg_by_seq = std.AutoHashMap(u32, *Segment).init(allocator),
            .active_seq = 0,
            .next_seq = 1,
            .target_segment_bytes = DEFAULT_SEGMENT_BYTES,
            .fsync_every = fsync_every,
            .shred_index = std.AutoHashMap(ShredKey, Loc).init(allocator),
            .slot_shreds = std.AutoHashMap(u64, std.ArrayListUnmanaged(u32)).init(allocator),
            .code_index = std.AutoHashMap(ShredKey, Loc).init(allocator),
            .slot_codes = std.AutoHashMap(u64, std.ArrayListUnmanaged(u32)).init(allocator),
            .slot_meta = std.AutoHashMap(u64, SlotMeta).init(allocator),
            .meta_seq = std.AutoHashMap(u64, u32).init(allocator),
            .roots = std.AutoHashMap(u64, u32).init(allocator),
            .erasure_meta = std.AutoHashMap(FecKey, StoredErasure).init(allocator),
            .merkle_meta = std.AutoHashMap(FecKey, StoredMerkle).init(allocator),
            .tx_status = std.AutoHashMap(SigSlotKey, StoredBytes).init(allocator),
            .sig_index = std.AutoHashMap([64]u8, u64).init(allocator),
            .memos = std.AutoHashMap(SigSlotKey, StoredBytes).init(allocator),
            .addr_sigs = std.AutoHashMap(AddrSigKey, StoredAddrSig).init(allocator),
            .addr_sig_index = std.AutoHashMap([32]u8, std.ArrayListUnmanaged(AddrSigEntry)).init(allocator),
            .rewards = std.AutoHashMap(u64, StoredBytes).init(allocator),
            .blocktime = std.AutoHashMap(u64, StoredI64).init(allocator),
            .block_height = std.AutoHashMap(u64, StoredU64).init(allocator),
            .blockhash = std.AutoHashMap(u64, StoredBlockhash).init(allocator),
            .flight = std.AutoHashMap(u64, StoredFlight).init(allocator),
            .bank_hashes = std.AutoHashMap(u64, StoredBankHash).init(allocator),
            .slot_sigs = std.AutoHashMap(SlotSigKey, u32).init(allocator),
            .slot_sig_index = std.AutoHashMap(u64, std.ArrayListUnmanaged(SlotSigEntry)).init(allocator),
            .tx_wire = std.AutoHashMap(SigSlotKey, StoredBytes).init(allocator),
        };
        errdefer self.freeSegments();
        errdefer self.shred_index.deinit();
        errdefer self.freeSlotList(&self.slot_shreds);
        errdefer self.code_index.deinit();
        errdefer self.freeSlotList(&self.slot_codes);
        errdefer self.slot_meta.deinit();
        errdefer self.meta_seq.deinit();
        errdefer self.roots.deinit();
        errdefer self.erasure_meta.deinit();
        errdefer self.merkle_meta.deinit();
        errdefer self.freeBytesMap(&self.tx_status);
        errdefer self.sig_index.deinit();
        errdefer self.freeBytesMap(&self.memos);
        errdefer self.addr_sigs.deinit();
        errdefer self.freeAddrSigIndex();
        errdefer self.freeBytesMap(&self.rewards);
        errdefer self.blocktime.deinit();
        errdefer self.block_height.deinit();
        errdefer self.blockhash.deinit();
        errdefer self.flight.deinit();
        errdefer self.bank_hashes.deinit();
        errdefer self.slot_sigs.deinit();
        errdefer self.freeSlotSigIndex();
        errdefer self.freeBytesMap(&self.tx_wire);

        // Open + replay every existing segment (and create a fresh active one
        // if none exist). No-op index if the dir is empty.
        try self.recoverAll();

        return self;
    }

    /// Close + free all segments (files closed, structs destroyed, map emptied).
    fn freeSegments(self: *VexLedger) void {
        var it = self.seg_by_seq.valueIterator();
        while (it.next()) |seg_ptr| {
            seg_ptr.*.file.close();
            self.allocator.destroy(seg_ptr.*);
        }
        self.seg_by_seq.deinit();
    }

    /// Free all owned memory (meta slices, maps, path dup), close every segment,
    /// and destroy the VexLedger.
    pub fn deinit(self: *VexLedger) void {
        // Free every owned completed_data_indexes slice first, then the map.
        var it = self.slot_meta.valueIterator();
        while (it.next()) |m| {
            self.freeMetaOwned(m.*);
        }
        self.slot_meta.deinit();
        self.meta_seq.deinit();
        self.shred_index.deinit();
        self.freeSlotList(&self.slot_shreds);
        self.code_index.deinit();
        self.freeSlotList(&self.slot_codes);
        self.roots.deinit();
        self.erasure_meta.deinit();
        self.merkle_meta.deinit();

        // RPC/execution-product CFs: free owned byte values, then the maps.
        self.freeBytesMap(&self.tx_status);
        self.sig_index.deinit();
        self.freeBytesMap(&self.memos);
        self.addr_sigs.deinit();
        self.freeAddrSigIndex();
        self.freeBytesMap(&self.rewards);
        self.blocktime.deinit();
        self.block_height.deinit();
        self.blockhash.deinit();
        self.flight.deinit();
        self.bank_hashes.deinit();
        self.slot_sigs.deinit();
        self.freeSlotSigIndex();
        self.freeBytesMap(&self.tx_wire);

        self.freeSegments();
        self.allocator.free(self.ledger_path);

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    // ── Segment management ──────────────────────────────────────────────────

    /// The active (appendable) segment. Never null after init (recovery always
    /// leaves a non-legacy active segment).
    fn activeSegment(self: *VexLedger) *Segment {
        return self.seg_by_seq.get(self.active_seq).?;
    }

    /// Open (or, with `create`, create-if-absent without truncating) a segment
    /// file and wrap it in a heap-allocated Segment. Legacy is opened read-only
    /// so the artifact is never mutated; `.seg` files are opened read+write.
    fn openSegment(self: *VexLedger, dir: std.fs.Dir, seq: u32, is_legacy: bool, create: bool) !*Segment {
        var namebuf: [64]u8 = undefined;
        const name = segFilename(seq, is_legacy, &namebuf);

        const file = if (create)
            try dir.createFile(name, .{ .read = true, .truncate = false })
        else if (is_legacy)
            try dir.openFile(name, .{ .mode = .read_only })
        else
            try dir.openFile(name, .{ .mode = .read_write });
        errdefer file.close();

        const seg = try self.allocator.create(Segment);
        errdefer self.allocator.destroy(seg);
        seg.* = .{ .seq = seq, .is_legacy = is_legacy, .file = file };

        try self.seg_by_seq.put(seq, seg);
        return seg;
    }

    /// Replay all segments on open, or create a fresh active segment if none.
    /// Scans legacy (seq 0) first, then `.seg` files by ascending seq so that
    /// last-wins overwrite (a re-put shred / re-written meta) resolves to the
    /// newest segment. Only the highest-seq `.seg` (the active one) has its torn
    /// tail truncated; legacy + sealed segments are scanned read-only.
    fn recoverAll(self: *VexLedger) !void {
        var dir = try std.fs.cwd().openDir(self.ledger_path, .{ .iterate = true });
        defer dir.close();

        // Enumerate: note the legacy log + collect `.seg` sequence numbers.
        var legacy_present = false;
        var seqs = std.ArrayListUnmanaged(u32){};
        defer seqs.deinit(self.allocator);

        var dir_it = dir.iterate();
        while (try dir_it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.eql(u8, entry.name, LEGACY_LOG_FILENAME)) {
                legacy_present = true;
                continue;
            }
            if (parseSegSeq(entry.name)) |seq| try seqs.append(self.allocator, seq);
        }
        std.mem.sort(u32, seqs.items, {}, std.sort.asc(u32));

        // Legacy log is the oldest segment (seq 0), scanned read-only.
        if (legacy_present) {
            const seg = try self.openSegment(dir, 0, true, false);
            try self.scanSegment(seg, false);
        }

        // Each `.seg` in ascending seq; the last is the active (appendable) one.
        for (seqs.items, 0..) |seq, i| {
            const is_active = (i == seqs.items.len - 1);
            const seg = try self.openSegment(dir, seq, false, false);
            try self.scanSegment(seg, is_active);
        }

        if (seqs.items.len > 0) {
            self.active_seq = seqs.items[seqs.items.len - 1];
            self.next_seq = self.active_seq + 1;
        } else {
            // No `.seg` files (empty dir, or legacy-only artifact). Create a fresh
            // active segment; writes go here, never into the legacy log.
            const seg = try self.openSegment(dir, 1, false, true);
            _ = seg;
            self.active_seq = 1;
            self.next_seq = 2;
        }
    }

    /// Scan one segment from offset 0, replaying every complete record into the
    /// index/meta/roots and computing the segment's write_offset + min/max slot.
    /// A short header or a payload running past EOF is treated as end-of-segment.
    /// When `truncate_torn` (active segment only), any torn tail is discarded so
    /// EOF == write_offset and the append invariant holds.
    fn scanSegment(self: *VexLedger, seg: *Segment, truncate_torn: bool) !void {
        const stat = try seg.file.stat();
        const size: u64 = stat.size;

        var offset: u64 = 0;
        while (offset + HEADER_LEN <= size) {
            var hdr: [HEADER_LEN]u8 = undefined;
            const got = try seg.file.pread(&hdr, offset);
            if (got < HEADER_LEN) break;

            const kind = hdr[0];
            const slot = std.mem.readInt(u64, hdr[1..9], .little);
            const aux = std.mem.readInt(u32, hdr[9..13], .little);
            const len = std.mem.readInt(u32, hdr[13..17], .little);

            const payload_offset = offset + HEADER_LEN;
            const record_end = payload_offset + len;
            if (record_end > size) break; // torn payload / bogus len → stop.

            switch (kind) {
                KIND_SHRED => {
                    const key: ShredKey = .{ .slot = slot, .index = aux };
                    const is_new = !self.shred_index.contains(key);
                    try self.shred_index.put(key, .{ .seq = seg.seq, .offset = payload_offset, .len = len });
                    if (is_new) try self.addToSlotList(&self.slot_shreds, slot, aux);
                },
                KIND_CODE => {
                    const key: ShredKey = .{ .slot = slot, .index = aux };
                    const is_new = !self.code_index.contains(key);
                    try self.code_index.put(key, .{ .seq = seg.seq, .offset = payload_offset, .len = len });
                    if (is_new) try self.addToSlotList(&self.slot_codes, slot, aux);
                },
                KIND_META => {
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    // Best-effort: a meta record written in a PRE-V3 format (an old
                    // ledger mixed in) won't decode as SlotMetaV3 — skip it (the
                    // slot's SHREDS are unaffected; raw) rather than abort recovery.
                    if (self.deserializeMeta(payload)) |m| {
                        if (try self.slot_meta.fetchPut(slot, m)) |old| {
                            self.freeMetaOwned(old.value);
                        }
                        try self.meta_seq.put(slot, seg.seq);
                    } else |_| {}
                },
                KIND_ROOT => {
                    try self.roots.put(slot, seg.seq);
                },
                KIND_ERASURE => {
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    const em = agave_wire.ErasureMeta.decode(payload) catch break; // torn/garbage → end.
                    try self.erasure_meta.put(.{ .slot = slot, .fec_set_index = aux }, .{ .meta = em, .seq = seg.seq });
                },
                KIND_MERKLE => {
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    const mm = agave_wire.MerkleRootMeta.decode(payload) catch break;
                    try self.merkle_meta.put(.{ .slot = slot, .fec_set_index = aux }, .{ .meta = mm, .seq = seg.seq });
                },
                KIND_TX_STATUS => {
                    // payload = sig[64] ++ protobuf_bytes. Need >= 64 for the key.
                    if (len < 64) break; // torn/garbage → end-of-segment.
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    var sig: [64]u8 = undefined;
                    @memcpy(&sig, payload[0..64]);
                    // sig_index.put before the ownership transfer (see put API):
                    // keeps the errdefer-guarded slice the last thing inserted.
                    try self.sig_index.put(sig, slot);
                    const owned = try self.allocator.dupe(u8, payload[64..]);
                    errdefer self.allocator.free(owned);
                    if (try self.tx_status.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = seg.seq })) |old| {
                        self.allocator.free(old.value.bytes);
                    }
                },
                KIND_MEMO => {
                    if (len < 64) break;
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    var sig: [64]u8 = undefined;
                    @memcpy(&sig, payload[0..64]);
                    const owned = try self.allocator.dupe(u8, payload[64..]);
                    errdefer self.allocator.free(owned);
                    if (try self.memos.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = seg.seq })) |old| {
                        self.allocator.free(old.value.bytes);
                    }
                },
                KIND_ADDR_SIG => {
                    // payload = pubkey[32] ++ tx_index(u32 LE) ++ sig[64] ++ writeable(1).
                    if (len != 32 + 4 + 64 + 1) break;
                    var payload: [32 + 4 + 64 + 1]u8 = undefined;
                    try preadExact(seg.file, &payload, payload_offset);
                    var pubkey: [32]u8 = undefined;
                    @memcpy(&pubkey, payload[0..32]);
                    const tx_index = std.mem.readInt(u32, payload[32..36], .little);
                    var sig: [64]u8 = undefined;
                    @memcpy(&sig, payload[36..100]);
                    const writeable = payload[100] != 0;
                    const prev = try self.addr_sigs.fetchPut(
                        .{ .pubkey = pubkey, .slot = slot, .tx_index = tx_index, .sig = sig },
                        .{ .writeable = writeable, .seq = seg.seq },
                    );
                    if (prev == null) {
                        try self.addrSigIndexInsertLocked(pubkey, .{ .slot = slot, .tx_index = tx_index, .sig = sig, .seq = seg.seq });
                    }
                },
                KIND_REWARDS => {
                    // payload = protobuf bytes (slot key in header).
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    const owned = try self.allocator.dupe(u8, payload);
                    errdefer self.allocator.free(owned);
                    if (try self.rewards.fetchPut(slot, .{ .bytes = owned, .seq = seg.seq })) |old| {
                        self.allocator.free(old.value.bytes);
                    }
                },
                KIND_BLOCKTIME => {
                    if (len != 8) break;
                    var payload: [8]u8 = undefined;
                    try preadExact(seg.file, &payload, payload_offset);
                    const ts = std.mem.readInt(i64, &payload, .little);
                    try self.blocktime.put(slot, .{ .value = ts, .seq = seg.seq });
                },
                KIND_BLOCKHEIGHT => {
                    if (len != 8) break;
                    var payload: [8]u8 = undefined;
                    try preadExact(seg.file, &payload, payload_offset);
                    const h = std.mem.readInt(u64, &payload, .little);
                    try self.block_height.put(slot, .{ .value = h, .seq = seg.seq });
                },
                KIND_BLOCKHASH => {
                    if (len != 32) break;
                    var hash: [32]u8 = undefined;
                    try preadExact(seg.file, &hash, payload_offset);
                    try self.blockhash.put(slot, .{ .hash = hash, .seq = seg.seq });
                },
                KIND_FLIGHT => {
                    // payload = the fixed 2152-byte FlightRecord (slot in header).
                    if (len != FlightRecord.PAYLOAD_LEN) break; // torn/garbage.
                    var payload: [FlightRecord.PAYLOAD_LEN]u8 = undefined;
                    try preadExact(seg.file, &payload, payload_offset);
                    try self.flight.put(slot, .{ .rec = FlightRecord.decode(&payload), .seq = seg.seq });
                },
                KIND_BANK_HASH => {
                    // payload = 37-byte wincode FrozenHashVersioned (slot in header).
                    if (len != agave_wire.FROZEN_HASH_LEN) break; // torn/garbage.
                    var payload: [agave_wire.FROZEN_HASH_LEN]u8 = undefined;
                    try preadExact(seg.file, &payload, payload_offset);
                    // Malformed (but exact-length) value → skip THIS record's insert
                    // and keep scanning (the rest of the segment is unaffected).
                    if (agave_wire.decodeFrozenHash(&payload)) |fh| {
                        try self.bank_hashes.put(slot, .{ .frozen_hash = fh.frozen_hash, .is_duplicate_confirmed = fh.is_duplicate_confirmed, .seq = seg.seq });
                    } else |_| {}
                },
                KIND_SLOT_SIG => {
                    // payload = sig[64]; slot in header; aux = tx_index.
                    if (len != 64) break;
                    var sig: [64]u8 = undefined;
                    try preadExact(seg.file, &sig, payload_offset);
                    const tx_index = aux;
                    const prev = try self.slot_sigs.fetchPut(.{ .slot = slot, .tx_index = tx_index }, seg.seq);
                    if (prev == null) {
                        try self.slotSigIndexInsertLocked(slot, .{ .tx_index = tx_index, .sig = sig, .seq = seg.seq });
                    }
                },
                KIND_TX_WIRE => {
                    // payload = sig[64] ++ wire. Need >= 64 for the key.
                    if (len < 64) break; // torn/garbage → end-of-segment.
                    const payload = try self.allocator.alloc(u8, len);
                    defer self.allocator.free(payload);
                    try preadExact(seg.file, payload, payload_offset);
                    var sig: [64]u8 = undefined;
                    @memcpy(&sig, payload[0..64]);
                    const owned = try self.allocator.dupe(u8, payload[64..]);
                    errdefer self.allocator.free(owned);
                    if (try self.tx_wire.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = seg.seq })) |old| {
                        self.allocator.free(old.value.bytes);
                    }
                },
                else => break, // unknown kind: corrupt/torn → end-of-segment.
            }

            seg.observeSlot(slot);
            offset = record_end;
        }

        seg.write_offset = offset;
        if (truncate_torn and offset < size) {
            try seg.file.setEndPos(offset);
        }
    }

    /// Seal the active segment (fsync) and open a fresh active segment. Called at
    /// a finishSlot boundary once the active segment reaches target_segment_bytes,
    /// so the next slot starts in a new segment (keeps slots mostly whole-in-one).
    fn rollSegment(self: *VexLedger) !void {
        const cur = self.activeSegment();
        try cur.file.sync(); // durably seal before we stop appending to it.

        var dir = try std.fs.cwd().openDir(self.ledger_path, .{});
        defer dir.close();

        const seq = self.next_seq;
        const seg = try self.openSegment(dir, seq, false, true);
        _ = seg;
        self.active_seq = seq;
        self.next_seq = seq + 1;
    }

    // ── Append helpers ──────────────────────────────────────────────────────

    /// Serialize a 17-byte header into `hdr`.
    fn writeHeader(hdr: *[HEADER_LEN]u8, kind: u8, slot: u64, aux: u32, len: u32) void {
        hdr[0] = kind;
        std.mem.writeInt(u64, hdr[1..9], slot, .little);
        std.mem.writeInt(u32, hdr[9..13], aux, .little);
        std.mem.writeInt(u32, hdr[13..17], len, .little);
    }

    /// Append one record (header + payload) to the ACTIVE segment at its
    /// write_offset and advance that segment's cursor + slot range. Returns the
    /// Loc (segment seq + payload offset + len) for indexing.
    fn appendRecord(self: *VexLedger, kind: u8, slot: u64, aux: u32, payload: []const u8) !Loc {
        const seg = self.activeSegment();

        var hdr: [HEADER_LEN]u8 = undefined;
        const len: u32 = @intCast(payload.len);
        writeHeader(&hdr, kind, slot, aux, len);

        // Seek to the AUTHORITATIVE append cursor (write_offset), NOT seekFromEnd:
        // after recovery discarded a torn tail, true-EOF may sit past write_offset.
        // recover() truncates the active segment's torn tail so EOF==write_offset,
        // but seeking explicitly keeps appendRecord correct regardless.
        try seg.file.seekTo(seg.write_offset);
        try seg.file.writeAll(&hdr);
        const payload_offset = seg.write_offset + HEADER_LEN;
        if (payload.len != 0) try seg.file.writeAll(payload);

        seg.write_offset += HEADER_LEN + payload.len;
        seg.observeSlot(slot);
        return .{ .seq = seg.seq, .offset = payload_offset, .len = len };
    }

    // ── Public write API ────────────────────────────────────────────────────

    /// Append a data-shred record and index it. De-dup is last-wins: a repeated
    /// (slot,index) overwrites the prior Loc (the old bytes stay in the segment
    /// but are no longer referenced). The caller's `wire_bytes` are copied into
    /// the segment; the slice is NOT retained.
    pub fn putShred(self: *VexLedger, slot: u64, index: u32, wire_bytes: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const key: ShredKey = .{ .slot = slot, .index = index };
        const is_new = !self.shred_index.contains(key);
        const loc = try self.appendRecord(KIND_SHRED, slot, index, wire_bytes);
        try self.shred_index.put(key, loc);
        // Add to the per-slot list only on FIRST sight (a re-put overwrites the
        // Loc but must not double-list the index).
        if (is_new) try self.addToSlotList(&self.slot_shreds, slot, index);
    }

    /// Append a CODING-shred record. @prov:ledger.column-families (code_shred) and index it. Same
    /// verbatim-store + last-wins semantics as putShred, into the separate coding
    /// index. Stored for repair-serve; Vexor's fec_resolver does the actual
    /// Reed-Solomon recovery upstream (the ledger is STORE-ONLY).
    pub fn putCodingShred(self: *VexLedger, slot: u64, index: u32, wire_bytes: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const key: ShredKey = .{ .slot = slot, .index = index };
        const is_new = !self.code_index.contains(key);
        const loc = try self.appendRecord(KIND_CODE, slot, index, wire_bytes);
        try self.code_index.put(key, loc);
        if (is_new) try self.addToSlotList(&self.slot_codes, slot, index);
    }

    /// Deep-copy `meta` (including completed_data_indexes), append a serialized
    /// kind=1 record, and store it in the slot_meta map (freeing any prior meta
    /// for this slot). The caller retains ownership of its own `meta` slice.
    pub fn finishSlot(self: *VexLedger, slot: u64, slot_meta: SlotMeta) !void {
        self.lock.lock();
        defer self.lock.unlock();
        // Serialize then append (slot's aux is unused for meta records => 0).
        const payload = try self.serializeMeta(slot, slot_meta);
        defer self.allocator.free(payload);
        const loc = try self.appendRecord(KIND_META, slot, 0, payload);

        try self.storeMeta(slot, slot_meta, loc.seq);

        // fsync cadence (VEX_LEDGER_FSYNC_EVERY): flushes this slot's shred records
        // (already written via direct file.writeAll → kernel-resident + readable
        // after a signal-kill) AND the meta record to DISK. Default (fsync_every<=1)
        // = one fsync per completed slot (the durable-offline-replay guarantee).
        // N>1 batches the fsync to once per N slots for throughput; only a hard
        // power-loss loses the <N-slot un-flushed tail, which is network-recoverable
        // (same posture as Firedancer, which doesn't persist shreds at all). One
        // fsync per slot (not per shred) is already cheap. Errors propagate; on the
        // live persist tap the caller catch-swallows (best-effort, never fatal).
        const seg = self.activeSegment();
        self.slots_since_fsync += 1;
        if (self.fsync_every <= 1 or self.slots_since_fsync >= self.fsync_every) {
            try seg.file.sync();
            self.slots_since_fsync = 0;
        }

        // Roll AFTER finishing this slot if the active segment is large enough, so
        // the NEXT slot starts a fresh segment (whole-slot-in-one-segment + lets
        // pruning unlink whole segments). rollSegment SEALS (fsyncs) the segment, so
        // a sealed segment is always durable even under batched fsync — reset the
        // batch counter. Roll failures must not corrupt the slot we just wrote —
        // propagate, leaving the current segment active.
        if (seg.write_offset >= self.target_segment_bytes) {
            try self.rollSegment();
            self.slots_since_fsync = 0;
        }
    }

    /// Append a root marker (kind=2) and record `slot` as rooted.
    pub fn setRoot(self: *VexLedger, slot: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const loc = try self.appendRecord(KIND_ROOT, slot, 0, &.{});
        try self.roots.put(slot, loc.seq);
    }

    /// Store an `erasure_meta` record. @prov:ledger.column-families (erasure_meta, byte-exact wire) The
    /// record's aux carries fec_set_index so recovery rebuilds the key. Last-wins.
    pub fn putErasureMeta(self: *VexLedger, slot: u64, fec_set_index: u32, em: agave_wire.ErasureMeta) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const payload = try em.encode(self.allocator);
        defer self.allocator.free(payload);
        const loc = try self.appendRecord(KIND_ERASURE, slot, fec_set_index, payload);
        try self.erasure_meta.put(.{ .slot = slot, .fec_set_index = fec_set_index }, .{ .meta = em, .seq = loc.seq });
    }

    /// Read an `erasure_meta` record (decoded). Null if absent.
    pub fn getErasureMeta(self: *VexLedger, slot: u64, fec_set_index: u32) ?agave_wire.ErasureMeta {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.erasure_meta.get(.{ .slot = slot, .fec_set_index = fec_set_index }) orelse return null;
        return e.meta;
    }

    /// Store a `merkle_root_meta` record. @prov:ledger.column-families (merkle_root_meta, byte-exact wire)
    pub fn putMerkleRootMeta(self: *VexLedger, slot: u64, fec_set_index: u32, mm: agave_wire.MerkleRootMeta) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const payload = try mm.encode(self.allocator);
        defer self.allocator.free(payload);
        const loc = try self.appendRecord(KIND_MERKLE, slot, fec_set_index, payload);
        try self.merkle_meta.put(.{ .slot = slot, .fec_set_index = fec_set_index }, .{ .meta = mm, .seq = loc.seq });
    }

    /// Read a `merkle_root_meta` record (decoded). Null if absent.
    pub fn getMerkleRootMeta(self: *VexLedger, slot: u64, fec_set_index: u32) ?agave_wire.MerkleRootMeta {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const m = self.merkle_meta.get(.{ .slot = slot, .fec_set_index = fec_set_index }) orelse return null;
        return m.meta;
    }

    // ── RPC / execution-product CFs (transaction_status, memos,
    //    address_signatures, rewards, blocktime, block_height) ───────────────
    //
    // Mirror the erasure_meta/merkle pattern: lock, frame the payload, append a
    // KIND_* record, store in the in-mem map keyed off the record's seq. The
    // sig/pubkey key can't fit the u32 `aux`, so it is framed in the payload
    // PREFIX (slot stays in the header); scanSegment parses it back on recovery.

    /// Store a `transaction_status` record. @prov:ledger.column-families (transaction_status) The
    /// VALUE is opaque protobuf bytes the CALLER pre-encodes (via agave_proto).
    /// Internal payload = sig[64] ++ protobuf_bytes (the sig framed in the prefix;
    /// slot in the header). Also updates `sig_index` (sig -> slot, latest-wins).
    /// Owned bytes are dup'd on put + freed on overwrite. Last-wins per (sig,slot).
    pub fn putTransactionStatus(self: *VexLedger, sig: [64]u8, slot: u64, protobuf_bytes: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const payload = try self.allocator.alloc(u8, 64 + protobuf_bytes.len);
        defer self.allocator.free(payload);
        @memcpy(payload[0..64], &sig);
        @memcpy(payload[64..], protobuf_bytes);
        const loc = try self.appendRecord(KIND_TX_STATUS, slot, 0, payload);

        // sig_index.put FIRST so the only fallible op AFTER the map takes
        // ownership of `owned` is the fetchPut itself: otherwise a later failing
        // insert would leave the errdefer freeing a slice the map now references
        // (double-free). A sig_index entry briefly pointing at a not-yet-inserted
        // status is non-fatal + self-heals on recovery (disk is the source of
        // truth). latest-wins point lookup.
        try self.sig_index.put(sig, slot);
        const owned = try self.allocator.dupe(u8, protobuf_bytes);
        errdefer self.allocator.free(owned);
        if (try self.tx_status.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = loc.seq })) |old| {
            self.allocator.free(old.value.bytes);
        }
    }

    /// Read a `transaction_status` value: an OWNED COPY of the stored protobuf
    /// bytes (caller frees with `allocator`), matching the `meta()` copy-out
    /// pattern. Null if (sig, slot) is absent.
    pub fn getTransactionStatus(self: *VexLedger, allocator: std.mem.Allocator, sig: [64]u8, slot: u64) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.tx_status.get(.{ .sig = sig, .slot = slot }) orelse return null;
        return try allocator.dupe(u8, e.bytes);
    }

    /// Latest slot a transaction_status was recorded for `sig`. @prov:ledger.column-families
    /// (TransactionStatusIndex point lookup). Null if the signature has no stored status.
    pub fn slotForSignature(self: *VexLedger, sig: [64]u8) ?u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.sig_index.get(sig);
    }

    /// Store a `transaction_memos` record. @prov:ledger.column-families (transaction_memos) The raw
    /// utf8 memo is stored (the wincode-String framing is produced only at an
    /// interop boundary). Internal payload = sig[64] ++ memo_utf8. Last-wins.
    pub fn putTransactionMemo(self: *VexLedger, sig: [64]u8, slot: u64, memo: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const payload = try self.allocator.alloc(u8, 64 + memo.len);
        defer self.allocator.free(payload);
        @memcpy(payload[0..64], &sig);
        @memcpy(payload[64..], memo);
        const loc = try self.appendRecord(KIND_MEMO, slot, 0, payload);

        const owned = try self.allocator.dupe(u8, memo);
        errdefer self.allocator.free(owned);
        if (try self.memos.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = loc.seq })) |old| {
            self.allocator.free(old.value.bytes);
        }
    }

    /// Read a `transaction_memos` value: an OWNED COPY of the raw memo utf8 bytes
    /// (caller frees). Null if (sig, slot) is absent.
    pub fn getTransactionMemo(self: *VexLedger, allocator: std.mem.Allocator, sig: [64]u8, slot: u64) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.memos.get(.{ .sig = sig, .slot = slot }) orelse return null;
        return try allocator.dupe(u8, e.bytes);
    }

    /// Store an `address_signatures` record. @prov:ledger.column-families (address_signatures) VALUE
    /// = a `writeable` bool. Internal payload = pubkey[32] ++ tx_index(u32 LE) ++
    /// sig[64] ++ writeable(1); slot in the header; aux carries tx_index. Last-wins.
    pub fn putAddressSignature(self: *VexLedger, pubkey: [32]u8, slot: u64, tx_index: u32, sig: [64]u8, writeable: bool) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var payload: [32 + 4 + 64 + 1]u8 = undefined;
        @memcpy(payload[0..32], &pubkey);
        std.mem.writeInt(u32, payload[32..36], tx_index, .little);
        @memcpy(payload[36..100], &sig);
        payload[100] = @intFromBool(writeable);
        const loc = try self.appendRecord(KIND_ADDR_SIG, slot, tx_index, &payload);

        // fetchPut returns the prior value if the key existed. Only insert into
        // the enumeration index on a NEW key, so a (rare/idempotent) re-put of
        // the same address-sig record never duplicates an enumeration entry.
        const prev = try self.addr_sigs.fetchPut(
            .{ .pubkey = pubkey, .slot = slot, .tx_index = tx_index, .sig = sig },
            .{ .writeable = writeable, .seq = loc.seq },
        );
        if (prev == null) {
            try self.addrSigIndexInsertLocked(pubkey, .{ .slot = slot, .tx_index = tx_index, .sig = sig, .seq = loc.seq });
        }
    }

    /// Append an entry to a pubkey's enumeration list (creating it if absent).
    /// Caller holds the exclusive lock.
    fn addrSigIndexInsertLocked(self: *VexLedger, pubkey: [32]u8, entry: AddrSigEntry) !void {
        const gop = try self.addr_sig_index.getOrPut(pubkey);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(self.allocator, entry);
    }

    /// Free every per-pubkey enumeration list, then the index map itself.
    fn freeAddrSigIndex(self: *VexLedger) void {
        var it = self.addr_sig_index.iterator();
        while (it.next()) |e| e.value_ptr.deinit(self.allocator);
        self.addr_sig_index.deinit();
    }

    /// rc.1 `get_confirmed_signatures_for_address2` ordering: (slot DESC,
    /// tx_index DESC) = reverse-chronological, newest first.
    fn cmpAddrSigDesc(_: void, a: AddrSigEntry, b: AddrSigEntry) bool {
        if (a.slot != b.slot) return a.slot > b.slot;
        return a.tx_index > b.tx_index;
    }
    fn findSigPos(entries: []const AddrSigEntry, sig: [64]u8) ?usize {
        for (entries, 0..) |e, i| if (std.mem.eql(u8, &e.sig, &sig)) return i;
        return null;
    }

    /// Enumerate a pubkey's signatures NEWEST-FIRST with rc.1
    /// `getSignaturesForAddress` semantics. Returns an OWNED slice (caller frees).
    ///
    /// - ORDER: (slot DESC, tx_index DESC) — reverse-chronological (rc.1
    ///   blockstore.rs:4296, reverse CF iteration over BE slot/tx_index keys).
    /// - `before_sig` EXCLUSIVE: results start strictly AFTER it (going back in
    ///   time). If `before_sig` is not among THIS address's sigs → empty (matches
    ///   rc.1's status-not-found → empty). See NOTE on cross-address resolution.
    /// - `until_sig` EXCLUSIVE: stop strictly BEFORE it; if not found → ignored.
    /// - `limit`: max rows returned (the RPC layer caps/validates 1..=1000).
    /// - `highest_slot` (optional): rc.1 upper bound — rows with `slot >
    ///   highest_slot` are skipped. Pass the handler's confirmed/rooted ceiling;
    ///   `null` = unbounded. The is_root/confirmed-unrooted gate itself is
    ///   RPC-layer state (commitment + bank), so it stays in the handler.
    ///
    /// NOTE (deviation flagged for the RPC wiring-plan): rc.1 resolves
    /// `before`/`until` to a (slot, block-position) via the GLOBAL transaction
    /// status, so a cursor sig from a DIFFERENT address still works. This
    /// accessor resolves the cursor within THIS address's own sig set (the
    /// standard pagination flow — clients page one address using sigs THIS method
    /// returned). For a cross-address cursor, the handler should pre-resolve it to
    /// a (slot, tx_index) and slice accordingly. Confirm against the handler
    /// contract before relying on cross-address cursors.
    pub fn getSignaturesForAddress(
        self: *VexLedger,
        allocator: std.mem.Allocator,
        pubkey: [32]u8,
        before_sig: ?[64]u8,
        until_sig: ?[64]u8,
        limit: usize,
        highest_slot: ?u64,
    ) ![]SignatureInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const list = self.addr_sig_index.get(pubkey) orelse return allocator.alloc(SignatureInfo, 0);
        // Snapshot + sort newest-first (a copy — never mutate the stored list).
        const entries = try allocator.alloc(AddrSigEntry, list.items.len);
        defer allocator.free(entries);
        @memcpy(entries, list.items);
        std.mem.sort(AddrSigEntry, entries, {}, cmpAddrSigDesc);

        // `before` EXCLUSIVE → start after its position; not-found → empty.
        var start: usize = 0;
        if (before_sig) |bs| {
            const pos = findSigPos(entries, bs) orelse return allocator.alloc(SignatureInfo, 0);
            start = pos + 1;
        }
        // `until` EXCLUSIVE → stop before its position; not-found → ignored.
        var end: usize = entries.len;
        if (until_sig) |us| {
            if (findSigPos(entries, us)) |pos| end = pos;
        }

        var out = std.ArrayListUnmanaged(SignatureInfo){};
        errdefer out.deinit(allocator);
        var i = start;
        while (i < end and out.items.len < limit) : (i += 1) {
            const e = entries[i];
            if (highest_slot) |hs| {
                if (e.slot > hs) continue; // rc.1 upper bound (skip future slots)
            }
            try out.append(allocator, .{ .signature = e.sig, .slot = e.slot, .tx_index = e.tx_index });
        }
        return out.toOwnedSlice(allocator);
    }

    /// Read an `address_signatures` value: the stored `writeable` bool, or null
    /// if the (pubkey, slot, tx_index, sig) key is absent.
    pub fn getAddressSignature(self: *VexLedger, pubkey: [32]u8, slot: u64, tx_index: u32, sig: [64]u8) ?bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.addr_sigs.get(.{ .pubkey = pubkey, .slot = slot, .tx_index = tx_index, .sig = sig }) orelse return null;
        return e.writeable;
    }

    /// Store a SLOT→SIGNATURE index record (Vexor-native, for getBlock's per-slot tx
    /// enumeration). `tx_index` = the tx's position in the block; `sig` = its signature.
    /// Internal payload = sig[64]; slot in the header; aux carries tx_index. The
    /// enumeration index dedups on (slot, tx_index) so an idempotent re-put never
    /// duplicates a row (first-write-wins, matching the addr_sig guard).
    pub fn putSlotSignature(self: *VexLedger, slot: u64, tx_index: u32, sig: [64]u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const loc = try self.appendRecord(KIND_SLOT_SIG, slot, tx_index, &sig);

        // Insert into the enumeration index only on a NEW (slot, tx_index) key.
        const prev = try self.slot_sigs.fetchPut(.{ .slot = slot, .tx_index = tx_index }, loc.seq);
        if (prev == null) {
            try self.slotSigIndexInsertLocked(slot, .{ .tx_index = tx_index, .sig = sig, .seq = loc.seq });
        }
    }

    /// Append an entry to a slot's enumeration list (creating it if absent).
    /// Caller holds the exclusive lock.
    fn slotSigIndexInsertLocked(self: *VexLedger, slot: u64, entry: SlotSigEntry) !void {
        const gop = try self.slot_sig_index.getOrPut(slot);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(self.allocator, entry);
    }

    /// Free every per-slot enumeration list, then the index map itself.
    fn freeSlotSigIndex(self: *VexLedger) void {
        var it = self.slot_sig_index.iterator();
        while (it.next()) |e| e.value_ptr.deinit(self.allocator);
        self.slot_sig_index.deinit();
    }

    /// Ascending-by-tx_index ordering = block (intra-slot execution) order.
    fn cmpSlotSigAsc(_: void, a: SlotSigEntry, b: SlotSigEntry) bool {
        return a.tx_index < b.tx_index;
    }

    /// Enumerate a slot's transaction signatures in BLOCK ORDER (tx_index ascending)
    /// for getBlock. Returns an OWNED slice (caller frees); empty if the slot has no
    /// recorded signatures.
    pub fn getSlotSignatures(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) ![]SlotSigInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const list = self.slot_sig_index.get(slot) orelse return allocator.alloc(SlotSigInfo, 0);
        // Snapshot + sort ascending (a copy — never mutate the stored list).
        const entries = try allocator.alloc(SlotSigEntry, list.items.len);
        defer allocator.free(entries);
        @memcpy(entries, list.items);
        std.mem.sort(SlotSigEntry, entries, {}, cmpSlotSigAsc);

        const out = try allocator.alloc(SlotSigInfo, entries.len);
        for (entries, 0..) |e, i| out[i] = .{ .tx_index = e.tx_index, .signature = e.sig };
        return out;
    }

    /// Store a transaction's raw WIRE bytes (Vexor-native KIND_TX_WIRE). Internal payload =
    /// sig[64] ++ wire; slot in the header. Owned bytes; last-wins per (sig, slot). Decoupled from
    /// sig_index (tx_status owns the point lookup; population stores status+wire together).
    pub fn putTransactionWire(self: *VexLedger, sig: [64]u8, slot: u64, wire: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const payload = try self.allocator.alloc(u8, 64 + wire.len);
        defer self.allocator.free(payload);
        @memcpy(payload[0..64], &sig);
        @memcpy(payload[64..], wire);
        const loc = try self.appendRecord(KIND_TX_WIRE, slot, 0, payload);

        const owned = try self.allocator.dupe(u8, wire);
        errdefer self.allocator.free(owned);
        if (try self.tx_wire.fetchPut(.{ .sig = sig, .slot = slot }, .{ .bytes = owned, .seq = loc.seq })) |old| {
            self.allocator.free(old.value.bytes);
        }
    }

    /// Read a transaction's raw WIRE bytes: an OWNED COPY (caller frees with `allocator`). Null if
    /// (sig, slot) has no stored wire.
    pub fn getTransactionWire(self: *VexLedger, allocator: std.mem.Allocator, sig: [64]u8, slot: u64) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.tx_wire.get(.{ .sig = sig, .slot = slot }) orelse return null;
        return try allocator.dupe(u8, e.bytes);
    }

    /// Store a `rewards` record. @prov:ledger.column-families (rewards) VALUE = opaque protobuf bytes
    /// the CALLER pre-encodes. Slot-keyed: payload is the protobuf bytes verbatim
    /// (slot in the header, no key prefix). Owned bytes; last-wins per slot.
    pub fn putRewards(self: *VexLedger, slot: u64, protobuf_bytes: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const loc = try self.appendRecord(KIND_REWARDS, slot, 0, protobuf_bytes);
        const owned = try self.allocator.dupe(u8, protobuf_bytes);
        errdefer self.allocator.free(owned);
        if (try self.rewards.fetchPut(slot, .{ .bytes = owned, .seq = loc.seq })) |old| {
            self.allocator.free(old.value.bytes);
        }
    }

    /// Read a `rewards` value: an OWNED COPY of the protobuf bytes (caller frees).
    /// Null if `slot` has no rewards record.
    pub fn getRewards(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.rewards.get(slot) orelse return null;
        return try allocator.dupe(u8, e.bytes);
    }

    /// Store a `blocktime` record. @prov:ledger.column-families (blocktime) VALUE = a bare i64 unix
    /// timestamp. Payload = 8-byte i64 LE (slot key in the header). Last-wins.
    pub fn putBlocktime(self: *VexLedger, slot: u64, ts: i64) !void {
        self.lock.lock();
        defer self.lock.unlock();
        var payload: [8]u8 = undefined;
        std.mem.writeInt(i64, &payload, ts, .little);
        const loc = try self.appendRecord(KIND_BLOCKTIME, slot, 0, &payload);
        try self.blocktime.put(slot, .{ .value = ts, .seq = loc.seq });
    }

    /// Read a `blocktime` value (i64), or null if `slot` has none.
    pub fn getBlocktime(self: *VexLedger, slot: u64) ?i64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.blocktime.get(slot) orelse return null;
        return e.value;
    }

    /// Store a `block_height` record. @prov:ledger.column-families (block_height) VALUE = a bare u64.
    /// Payload = 8-byte u64 LE (slot key in the header). Last-wins.
    pub fn putBlockHeight(self: *VexLedger, slot: u64, h: u64) !void {
        self.lock.lock();
        defer self.lock.unlock();
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, h, .little);
        const loc = try self.appendRecord(KIND_BLOCKHEIGHT, slot, 0, &payload);
        try self.block_height.put(slot, .{ .value = h, .seq = loc.seq });
    }

    /// Read a `block_height` value (u64), or null if `slot` has none.
    pub fn getBlockHeight(self: *VexLedger, slot: u64) ?u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.block_height.get(slot) orelse return null;
        return e.value;
    }

    /// Store a slot's PoH blockhash (Vexor-native KIND_BLOCKHASH; getBlock blockhash/previousBlockhash).
    /// Payload = blockhash[32] (slot key in header). Last-wins.
    pub fn putBlockhash(self: *VexLedger, slot: u64, blockhash_bytes: [32]u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const loc = try self.appendRecord(KIND_BLOCKHASH, slot, 0, &blockhash_bytes);
        try self.blockhash.put(slot, .{ .hash = blockhash_bytes, .seq = loc.seq });
    }

    /// Read a slot's blockhash ([32]u8), or null if `slot` has none stored.
    pub fn getBlockhash(self: *VexLedger, slot: u64) ?[32]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.blockhash.get(slot) orelse return null;
        return e.hash;
    }

    /// Store a per-slot FLIGHT RECORD (P5 #1) — the bank_hash INPUT decomposition
    /// read off the frozen bank at freeze time. Payload = the fixed 2152-byte
    /// FlightRecord (slot key in the header). Last-wins. The CALLER (the fix105
    /// freeze tap) gates this on the `VEX_LEDGER_FLIGHT` env; the module just
    /// stores. Stored by value (no allocation, no free).
    pub fn putFlightRecord(self: *VexLedger, slot: u64, rec: FlightRecord) !void {
        self.lock.lock();
        defer self.lock.unlock();
        var payload: [FlightRecord.PAYLOAD_LEN]u8 = undefined;
        rec.encode(&payload);
        const loc = try self.appendRecord(KIND_FLIGHT, slot, 0, &payload);
        try self.flight.put(slot, .{ .rec = rec, .seq = loc.seq });
    }

    /// Read a slot's FlightRecord (by value), or null if `slot` has none.
    pub fn getFlightRecord(self: *VexLedger, slot: u64) ?FlightRecord {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.flight.get(slot) orelse return null;
        return e.rec;
    }

    /// Store a `bank_hashes` record. @prov:ledger.column-families (bank_hashes, byte-exact) VALUE =
    /// the 37-byte wincode FrozenHashVersioned::Current (slot key in the header).
    /// Last-wins. The on-disk bytes are the canonical wire (re-readable by
    /// ledger-tool given the BE slot key — agave_wire.slotKey).
    pub fn putBankHash(self: *VexLedger, slot: u64, frozen_hash: [32]u8, is_duplicate_confirmed: bool) !void {
        self.lock.lock();
        defer self.lock.unlock();
        var payload: [agave_wire.FROZEN_HASH_LEN]u8 = undefined;
        agave_wire.encodeFrozenHash(&payload, frozen_hash, is_duplicate_confirmed);
        const loc = try self.appendRecord(KIND_BANK_HASH, slot, 0, &payload);
        try self.bank_hashes.put(slot, .{ .frozen_hash = frozen_hash, .is_duplicate_confirmed = is_duplicate_confirmed, .seq = loc.seq });
    }

    /// Read a slot's bank_hashes value, or null if `slot` has none.
    pub fn getBankHash(self: *VexLedger, slot: u64) ?agave_wire.FrozenHash {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const e = self.bank_hashes.get(slot) orelse return null;
        return .{ .frozen_hash = e.frozen_hash, .is_duplicate_confirmed = e.is_duplicate_confirmed };
    }

    // ── Pruning / eviction (Phase 4b) ───────────────────────────────────────
    //
    // `--limit-ledger-size` semantics: keep a bounded recent window, evict the
    // OLDEST whole segments. Eviction is whole-segment `unlink()` (O(1), no
    // compaction copying), driven by per-segment `max_slot` so a segment is
    // dropped only when EVERY record it holds is below the keep-floor. The active
    // segment is never evicted. `unlink()` is the crash-commit point: recovery
    // rebuilds the index from whatever segments survive, so a crash mid-prune is
    // always consistent (the in-memory drop that follows is just bookkeeping the
    // next recover would redo anyway).

    /// Total on-disk bytes across all live segments (sum of write_offsets).
    pub fn byteSize(self: *VexLedger) u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.byteSizeLocked();
    }

    fn byteSizeLocked(self: *VexLedger) u64 {
        var total: u64 = 0;
        var it = self.seg_by_seq.valueIterator();
        while (it.next()) |sp| total += sp.*.write_offset;
        return total;
    }

    /// Evict every whole sealed segment whose max_slot < `keep_floor` (every
    /// record it holds is below the floor). The active segment is never evicted.
    /// Interleaving-safe (a segment straddling the floor is kept whole until the
    /// floor passes its highest slot). Returns reclamation stats.
    pub fn purgeSlotsBelow(self: *VexLedger, keep_floor: u64) !PruneStats {
        self.lock.lock();
        defer self.lock.unlock();
        return self.purgeSlotsBelowLocked(keep_floor);
    }

    fn purgeSlotsBelowLocked(self: *VexLedger, keep_floor: u64) !PruneStats {
        var victims = std.ArrayListUnmanaged(u32){};
        defer victims.deinit(self.allocator);
        var it = self.seg_by_seq.valueIterator();
        while (it.next()) |sp| {
            const seg = sp.*;
            if (seg.seq == self.active_seq) continue;
            const mx = seg.max_slot orelse continue; // empty sealed segment: nothing to reclaim.
            if (mx < keep_floor) try victims.append(self.allocator, seg.seq);
        }
        return self.evictVictimsLocked(victims.items);
    }

    /// Keep approximately the last `keep_slots` slots: evict whole segments below
    /// floor = (highest_slot + 1) - keep_slots. No-op if the ledger spans fewer.
    pub fn pruneToSlotWindow(self: *VexLedger, keep_slots: u64) !PruneStats {
        self.lock.lock();
        defer self.lock.unlock();
        const hi = self.highestSlotLocked() orelse return .{};
        if (keep_slots == 0) return self.purgeSlotsBelowLocked(hi + 1);
        if (hi + 1 <= keep_slots) return .{ .lowest_kept = self.lowestMinSlotLocked() };
        return self.purgeSlotsBelowLocked(hi + 1 - keep_slots);
    }

    /// Best-effort byte bound (FIFO ring): unlink the
    /// OLDEST sealed segments (ascending seq) until total on-disk size <=
    /// `max_bytes`, or only the active segment remains. Whole segments only.
    pub fn pruneToByteLimit(self: *VexLedger, max_bytes: u64) !PruneStats {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.byteSizeLocked() <= max_bytes) {
            return .{ .lowest_kept = self.lowestMinSlotLocked() };
        }

        var seqs = std.ArrayListUnmanaged(u32){};
        defer seqs.deinit(self.allocator);
        var it = self.seg_by_seq.keyIterator();
        while (it.next()) |k| {
            if (k.* != self.active_seq) try seqs.append(self.allocator, k.*);
        }
        std.mem.sort(u32, seqs.items, {}, std.sort.asc(u32)); // oldest first.

        var victims = std.ArrayListUnmanaged(u32){};
        defer victims.deinit(self.allocator);
        var running = self.byteSizeLocked();
        for (seqs.items) |seq| {
            if (running <= max_bytes) break;
            running -= self.seg_by_seq.get(seq).?.write_offset;
            try victims.append(self.allocator, seq);
        }
        return self.evictVictimsLocked(victims.items);
    }

    /// Unlink each victim segment file (crash-commit) THEN drop the in-memory
    /// entries it backed (shreds via Loc.seq, metas via meta_seq, roots via their
    /// seq). Disk is the source of truth, so post-unlink the in-mem sweep can
    /// never leave a dangling reference: every dropped key pointed into an
    /// unlinked segment, and every surviving key still has on-disk backing.
    fn evictVictimsLocked(self: *VexLedger, victim_seqs: []const u32) !PruneStats {
        var stats: PruneStats = .{};
        if (victim_seqs.len == 0) {
            stats.lowest_kept = self.lowestMinSlotLocked();
            return stats;
        }

        var victim_set = std.AutoHashMap(u32, void).init(self.allocator);
        defer victim_set.deinit();
        for (victim_seqs) |seq| try victim_set.put(seq, {});

        var dir = try std.fs.cwd().openDir(self.ledger_path, .{});
        defer dir.close();

        // 1. Unlink files + drop Segment structs (the durable commit).
        for (victim_seqs) |seq| {
            const seg = self.seg_by_seq.get(seq) orelse continue;
            var namebuf: [64]u8 = undefined;
            const name = segFilename(seg.seq, seg.is_legacy, &namebuf);
            const seg_bytes = seg.write_offset;
            seg.file.close();
            dir.deleteFile(name) catch |err| {
                if (err != error.FileNotFound) return err; // already gone (crashed prune) = reclaimed.
            };
            _ = self.seg_by_seq.remove(seq);
            self.allocator.destroy(seg);
            stats.bytes_freed += seg_bytes;
            stats.segments_unlinked += 1;
        }

        // 2. shred_index entries whose backing segment was unlinked.
        var dead_keys = std.ArrayListUnmanaged(ShredKey){};
        defer dead_keys.deinit(self.allocator);
        var si = self.shred_index.iterator();
        while (si.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_keys.append(self.allocator, e.key_ptr.*);
        }
        for (dead_keys.items) |k| {
            _ = self.shred_index.remove(k);
            self.removeFromSlotList(&self.slot_shreds, k.slot, k.index); // keep data list in sync.
            stats.shreds_dropped += 1;
        }

        // 2b. coding-shred entries backed by an unlinked segment (mirror of above).
        var dead_codes = std.ArrayListUnmanaged(ShredKey){};
        defer dead_codes.deinit(self.allocator);
        var ci = self.code_index.iterator();
        while (ci.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_codes.append(self.allocator, e.key_ptr.*);
        }
        for (dead_codes.items) |k| {
            _ = self.code_index.remove(k);
            self.removeFromSlotList(&self.slot_codes, k.slot, k.index);
            stats.codes_dropped += 1;
        }

        // 3. meta entries (free owned slices) + their meta_seq mirror.
        var dead_metas = std.ArrayListUnmanaged(u64){};
        defer dead_metas.deinit(self.allocator);
        var mi = self.meta_seq.iterator();
        while (mi.next()) |e| {
            if (victim_set.contains(e.value_ptr.*)) try dead_metas.append(self.allocator, e.key_ptr.*);
        }
        for (dead_metas.items) |slot| {
            if (self.slot_meta.fetchRemove(slot)) |kv| self.freeMetaOwned(kv.value);
            _ = self.meta_seq.remove(slot);
            stats.metas_dropped += 1;
        }

        // 4. root entries whose backing segment was unlinked.
        var dead_roots = std.ArrayListUnmanaged(u64){};
        defer dead_roots.deinit(self.allocator);
        var ri = self.roots.iterator();
        while (ri.next()) |e| {
            if (victim_set.contains(e.value_ptr.*)) try dead_roots.append(self.allocator, e.key_ptr.*);
        }
        for (dead_roots.items) |slot| {
            _ = self.roots.remove(slot);
            stats.roots_dropped += 1;
        }

        // 5. erasure_meta + merkle_root_meta entries backed by an unlinked segment.
        var dead_fec = std.ArrayListUnmanaged(FecKey){};
        defer dead_fec.deinit(self.allocator);
        var ei = self.erasure_meta.iterator();
        while (ei.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_fec.append(self.allocator, e.key_ptr.*);
        }
        for (dead_fec.items) |k| _ = self.erasure_meta.remove(k);
        dead_fec.clearRetainingCapacity();
        var mi2 = self.merkle_meta.iterator();
        while (mi2.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_fec.append(self.allocator, e.key_ptr.*);
        }
        for (dead_fec.items) |k| _ = self.merkle_meta.remove(k);

        // 6. G6 LOCKSTEP EVICTION — the sig/pubkey-keyed RPC/execution-product
        //    CFs (transaction_status, memos, address_signatures) are NOT slot-
        //    prefixed, so they cannot be range-deleted by slot like RocksDB's
        //    compaction filter would. They must be dropped exactly with the
        //    segment that backs them: collect keys whose stored `.seq` was
        //    unlinked, then remove (freeing owned bytes for the byte-valued maps).
        //    The slot-keyed CFs (rewards, blocktime, block_height) get the same
        //    seq-based sweep for prune-precision (a slot's record can live in a
        //    later segment than its shreds).

        // 6a. transaction_status (free owned bytes) + drop its sig_index entry.
        var dead_txs = std.ArrayListUnmanaged(SigSlotKey){};
        defer dead_txs.deinit(self.allocator);
        var txi = self.tx_status.iterator();
        while (txi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_txs.append(self.allocator, e.key_ptr.*);
        }
        for (dead_txs.items) |k| {
            if (self.tx_status.fetchRemove(k)) |kv| self.allocator.free(kv.value.bytes);
            // Drop the sig_index point lookup iff it still points at the dropped
            // slot (a newer status for the same sig in a surviving segment wins).
            if (self.sig_index.get(k.sig)) |s| {
                if (s == k.slot) _ = self.sig_index.remove(k.sig);
            }
            stats.tx_status_dropped += 1;
        }

        // 6b. transaction_memos (free owned bytes).
        var dead_memos = std.ArrayListUnmanaged(SigSlotKey){};
        defer dead_memos.deinit(self.allocator);
        var mmi = self.memos.iterator();
        while (mmi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_memos.append(self.allocator, e.key_ptr.*);
        }
        for (dead_memos.items) |k| {
            if (self.memos.fetchRemove(k)) |kv| self.allocator.free(kv.value.bytes);
            stats.memos_dropped += 1;
        }

        // 6c. address_signatures (no owned bytes).
        var dead_addrs = std.ArrayListUnmanaged(AddrSigKey){};
        defer dead_addrs.deinit(self.allocator);
        var ai = self.addr_sigs.iterator();
        while (ai.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_addrs.append(self.allocator, e.key_ptr.*);
        }
        for (dead_addrs.items) |k| {
            _ = self.addr_sigs.remove(k);
            stats.addr_sigs_dropped += 1;
        }
        // 6c'. addr_sig_index (lockstep): compact each pubkey list to its
        // surviving entries; remove a pubkey whose list becomes empty.
        var dead_pubkeys = std.ArrayListUnmanaged([32]u8){};
        defer dead_pubkeys.deinit(self.allocator);
        var aii = self.addr_sig_index.iterator();
        while (aii.next()) |e| {
            const list = e.value_ptr;
            var w: usize = 0;
            for (list.items) |entry| {
                if (!victim_set.contains(entry.seq)) {
                    list.items[w] = entry;
                    w += 1;
                }
            }
            list.shrinkRetainingCapacity(w);
            if (w == 0) try dead_pubkeys.append(self.allocator, e.key_ptr.*);
        }
        for (dead_pubkeys.items) |pk| {
            if (self.addr_sig_index.fetchRemove(pk)) |kv| {
                var l = kv.value;
                l.deinit(self.allocator);
            }
        }

        // 6d. rewards (slot-keyed, free owned bytes).
        var dead_rewards = std.ArrayListUnmanaged(u64){};
        defer dead_rewards.deinit(self.allocator);
        var rwi = self.rewards.iterator();
        while (rwi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_rewards.append(self.allocator, e.key_ptr.*);
        }
        for (dead_rewards.items) |slot| {
            if (self.rewards.fetchRemove(slot)) |kv| self.allocator.free(kv.value.bytes);
            stats.rewards_dropped += 1;
        }

        // 6e. blocktime (slot-keyed).
        var dead_bt = std.ArrayListUnmanaged(u64){};
        defer dead_bt.deinit(self.allocator);
        var bti = self.blocktime.iterator();
        while (bti.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_bt.append(self.allocator, e.key_ptr.*);
        }
        for (dead_bt.items) |slot| {
            _ = self.blocktime.remove(slot);
            stats.blocktime_dropped += 1;
        }

        // 6f. block_height (slot-keyed).
        var dead_bh = std.ArrayListUnmanaged(u64){};
        defer dead_bh.deinit(self.allocator);
        var bhi = self.block_height.iterator();
        while (bhi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_bh.append(self.allocator, e.key_ptr.*);
        }
        for (dead_bh.items) |slot| {
            _ = self.block_height.remove(slot);
            stats.block_height_dropped += 1;
        }

        // 6f'. blockhash (slot-keyed).
        var dead_bhh = std.ArrayListUnmanaged(u64){};
        defer dead_bhh.deinit(self.allocator);
        var bhhi = self.blockhash.iterator();
        while (bhhi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_bhh.append(self.allocator, e.key_ptr.*);
        }
        for (dead_bhh.items) |slot| {
            _ = self.blockhash.remove(slot);
            stats.blockhash_dropped += 1;
        }

        // 6g. flight (P5 #1, slot-keyed, no owned bytes).
        var dead_fl = std.ArrayListUnmanaged(u64){};
        defer dead_fl.deinit(self.allocator);
        var fli = self.flight.iterator();
        while (fli.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_fl.append(self.allocator, e.key_ptr.*);
        }
        for (dead_fl.items) |slot| {
            _ = self.flight.remove(slot);
            stats.flight_dropped += 1;
        }

        // 6h. bank_hashes (slot-keyed, no owned bytes).
        var dead_bhash = std.ArrayListUnmanaged(u64){};
        defer dead_bhash.deinit(self.allocator);
        var bhashi = self.bank_hashes.iterator();
        while (bhashi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_bhash.append(self.allocator, e.key_ptr.*);
        }
        for (dead_bhash.items) |slot| {
            _ = self.bank_hashes.remove(slot);
            stats.bank_hashes_dropped += 1;
        }

        // 6i. slot_sigs dedup-guard (slot/tx_index-keyed, value = seq).
        var dead_ss = std.ArrayListUnmanaged(SlotSigKey){};
        defer dead_ss.deinit(self.allocator);
        var ssi = self.slot_sigs.iterator();
        while (ssi.next()) |e| {
            if (victim_set.contains(e.value_ptr.*)) try dead_ss.append(self.allocator, e.key_ptr.*);
        }
        for (dead_ss.items) |k| {
            _ = self.slot_sigs.remove(k);
            stats.slot_sigs_dropped += 1;
        }
        // 6i'. slot_sig_index (lockstep): compact each slot list to its surviving
        // entries; remove a slot whose list becomes empty.
        var dead_ss_slots = std.ArrayListUnmanaged(u64){};
        defer dead_ss_slots.deinit(self.allocator);
        var ssii = self.slot_sig_index.iterator();
        while (ssii.next()) |e| {
            const list = e.value_ptr;
            var w: usize = 0;
            for (list.items) |entry| {
                if (!victim_set.contains(entry.seq)) {
                    list.items[w] = entry;
                    w += 1;
                }
            }
            list.shrinkRetainingCapacity(w);
            if (w == 0) try dead_ss_slots.append(self.allocator, e.key_ptr.*);
        }
        for (dead_ss_slots.items) |slot| {
            if (self.slot_sig_index.fetchRemove(slot)) |kv| {
                var l = kv.value;
                l.deinit(self.allocator);
            }
        }

        // 6j. tx_wire ((sig,slot)-keyed, free owned bytes). No sig_index touch (tx_status owns it).
        var dead_tw = std.ArrayListUnmanaged(SigSlotKey){};
        defer dead_tw.deinit(self.allocator);
        var twi = self.tx_wire.iterator();
        while (twi.next()) |e| {
            if (victim_set.contains(e.value_ptr.seq)) try dead_tw.append(self.allocator, e.key_ptr.*);
        }
        for (dead_tw.items) |k| {
            if (self.tx_wire.fetchRemove(k)) |kv| self.allocator.free(kv.value.bytes);
            stats.tx_wire_dropped += 1;
        }

        stats.lowest_kept = self.lowestMinSlotLocked();
        return stats;
    }

    /// Lowest `min_slot` across surviving segments (null if none hold records).
    /// This is the prune watermark: the ledger guarantees nothing below it.
    fn lowestMinSlotLocked(self: *VexLedger) ?u64 {
        var result: ?u64 = null;
        var it = self.seg_by_seq.valueIterator();
        while (it.next()) |sp| {
            if (sp.*.min_slot) |mn| {
                if (result == null or mn < result.?) result = mn;
            }
        }
        return result;
    }

    // ── Public read API ─────────────────────────────────────────────────────

    /// Read a shred's wire bytes from its segment into a NEW allocation owned by
    /// the CALLER (the caller must free it with the same allocator passed to
    /// `init`). Returns null if (slot,index) is not present.
    pub fn getShred(self: *VexLedger, slot: u64, index: u32) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const loc = self.shred_index.get(.{ .slot = slot, .index = index }) orelse return null;
        const seg = self.seg_by_seq.get(loc.seq) orelse return VexLedgerError.DanglingSegmentRef;
        const buf = try self.allocator.alloc(u8, loc.len);
        errdefer self.allocator.free(buf);
        try preadExact(seg.file, buf, loc.offset);
        return buf;
    }

    /// Return the sorted-ascending list of data-shred indices present for
    /// `slot`, allocated from `allocator` (caller frees). Empty slice if none.
    pub fn getSlotShredIndices(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) ![]u32 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.sortedSlotList(&self.slot_shreds, allocator, slot);
    }

    /// Read a coding shred's wire bytes. @prov:ledger.column-families (code_shred) Caller frees.
    pub fn getCodingShred(self: *VexLedger, slot: u64, index: u32) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const loc = self.code_index.get(.{ .slot = slot, .index = index }) orelse return null;
        const seg = self.seg_by_seq.get(loc.seq) orelse return VexLedgerError.DanglingSegmentRef;
        const buf = try self.allocator.alloc(u8, loc.len);
        errdefer self.allocator.free(buf);
        try preadExact(seg.file, buf, loc.offset);
        return buf;
    }

    /// Sorted-ascending coding-shred indices present for `slot`. @prov:ledger.column-families
    /// (index CF, `coding` half). Caller frees.
    pub fn getCodingShredIndices(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) ![]u32 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.sortedSlotList(&self.slot_codes, allocator, slot);
    }

    /// Derive the `index` CF value (8232 B, byte-exact wincode) for `slot`.
    /// @prov:ledger.column-families (index)
    /// from the in-memory per-slot lists: slot u64 LE + data ShredIndex + coding
    /// ShredIndex. VexLedger does NOT persist a redundant index record — this is
    /// produced on demand from the actual stored shreds (a BEAT: can't drift from
    /// what's really stored). Caller frees. Returns null if the slot has no shreds.
    pub fn getIndexBytes(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) !?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const has_data = self.slot_shreds.contains(slot);
        const has_code = self.slot_codes.contains(slot);
        if (!has_data and !has_code) return null;
        const data = try self.sortedSlotList(&self.slot_shreds, allocator, slot);
        defer allocator.free(data);
        const code = try self.sortedSlotList(&self.slot_codes, allocator, slot);
        defer allocator.free(code);
        return try agave_wire.encodeIndex(allocator, slot, data, code);
    }

    /// One data shred returned by getDataShredsForSlot (index + owned wire bytes).
    pub const DataShred = struct { index: u32, wire: []u8 };

    /// Ordered-by-index raw DATA shreds for `slot` — the get_slot_entries /
    /// repair-serve / archival-block byte SOURCE. Caller frees each `.wire` and the
    /// returned slice. The entry assembly (strip shred headers, concat
    /// completed_data_indexes ranges) + bincode-deserialize into Entries stays on
    /// the PROVEN fix105 ShredAssembler side — the std-only module serves the raw
    /// shreds it stored (the same bytes Boot-B replays bank-exactly), it does not
    /// re-implement shred-format/entry parsing. A rooted-only archival read gates
    /// on `isRoot(slot)`.
    pub fn getDataShredsForSlot(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) ![]DataShred {
        const idxs = try self.getSlotShredIndices(allocator, slot); // sorted ascending
        defer allocator.free(idxs);
        const out = try allocator.alloc(DataShred, idxs.len);
        errdefer allocator.free(out);
        var n: usize = 0;
        errdefer for (out[0..n]) |d| allocator.free(d.wire);
        for (idxs) |idx| {
            const wire = (try self.getShred(slot, idx)) orelse continue; // concurrent-prune race → skip
            out[n] = .{ .index = idx, .wire = wire };
            n += 1;
        }
        return out[0..n];
    }

    /// Copy a per-slot index list (data or coding), sorted ascending. Caller frees.
    fn sortedSlotList(self: *VexLedger, map: *SlotListMap, allocator: std.mem.Allocator, slot: u64) ![]u32 {
        _ = self;
        const lst = map.get(slot) orelse return allocator.alloc(u32, 0);
        const out = try allocator.dupe(u32, lst.items);
        errdefer allocator.free(out);
        std.mem.sort(u32, out, {}, std.sort.asc(u32));
        return out;
    }

    /// Return an OWNED deep copy of the stored SlotMeta for `slot` (the caller
    /// frees `completed_data_indexes` with `allocator`). Null if no meta stored.
    /// A COPY, not a borrow: safe to read concurrently with a writer overwriting
    /// the same slot's meta (a borrowed slice would be a use-after-free when the
    /// writer frees the prior slice). `completed_data_indexes` is always a freshly
    /// allocated slice (possibly empty) the caller owns.
    pub fn meta(self: *VexLedger, allocator: std.mem.Allocator, slot: u64) !?SlotMeta {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const m = self.slot_meta.get(slot) orelse return null;
        var copy = m;
        copy.completed_data_indexes = try allocator.dupe(u32, m.completed_data_indexes);
        errdefer allocator.free(copy.completed_data_indexes);
        copy.next_slots = try allocator.dupe(u64, m.next_slots);
        return copy;
    }

    /// Whether `slot` has been marked as a root.
    pub fn isRoot(self: *VexLedger, slot: u64) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.roots.contains(slot);
    }

    // ── Ordered iteration (G4). @prov:ledger.ordered-iteration ──
    //
    // The canonical slot_meta / rooted_slot iterators rely on RocksDB's BE-sorted
    // keys for in-order traversal.
    // VexLedger materializes the ordered slot list on demand (collect + sort) —
    // these are COLD paths (snapshot, orphan-repair, startup), not the hot insert
    // path, so an O(m log m) sort per call is fine and keeps the hot path O(1).

    /// Ascending list of slots (>= `from_slot`) that have a stored SlotMeta —
    /// the `slot_meta_iterator(from)` contract. Caller frees the returned slice.
    pub fn slotMetaSlotsFrom(self: *VexLedger, allocator: std.mem.Allocator, from_slot: u64) ![]u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.collectSortedKeysFrom(SlotMeta, allocator, &self.slot_meta, from_slot);
    }

    /// Ascending list of rooted slots (>= `from_slot`) — the `rooted_slot_iterator`
    /// contract. Caller frees the returned slice.
    pub fn rootedSlotsFrom(self: *VexLedger, allocator: std.mem.Allocator, from_slot: u64) ![]u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.collectSortedKeysFrom(u32, allocator, &self.roots, from_slot);
    }

    /// Collect a map's u64 keys >= `from`, ascending. `V` is the map's value type
    /// (SlotMeta for slot_meta, u32 for roots). Caller frees.
    fn collectSortedKeysFrom(
        self: *VexLedger,
        comptime V: type,
        allocator: std.mem.Allocator,
        map: *std.AutoHashMap(u64, V),
        from: u64,
    ) ![]u64 {
        _ = self;
        var list = std.ArrayListUnmanaged(u64){};
        errdefer list.deinit(allocator);
        var it = map.keyIterator();
        while (it.next()) |k| {
            if (k.* >= from) try list.append(allocator, k.*);
        }
        const out = try list.toOwnedSlice(allocator);
        std.mem.sort(u64, out, {}, std.sort.asc(u64));
        return out;
    }

    /// Lowest slot present in the shred index (null if empty).
    pub fn lowestSlot(self: *VexLedger) ?u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.lowestSlotLocked();
    }

    fn lowestSlotLocked(self: *VexLedger) ?u64 {
        // O(#slots-with-shreds), not O(total-shreds): iterate the per-slot map keys.
        var result: ?u64 = null;
        var it = self.slot_shreds.keyIterator();
        while (it.next()) |k| {
            if (result == null or k.* < result.?) result = k.*;
        }
        return result;
    }

    /// Highest slot present in the shred index (null if empty).
    pub fn highestSlot(self: *VexLedger) ?u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.highestSlotLocked();
    }

    fn highestSlotLocked(self: *VexLedger) ?u64 {
        var result: ?u64 = null;
        var it = self.slot_shreds.keyIterator();
        while (it.next()) |k| {
            if (result == null or k.* > result.?) result = k.*;
        }
        return result;
    }

    // ── SlotMeta (de)serialization + ownership ──────────────────────────────

    /// Serialize a SlotMeta to the byte-exact wire form. @prov:ledger.slot-meta-wire
    /// (via agave_wire). `slot` is the CF key, not stored in the struct. Widens my
    /// u32 received/consumed/last_index to the V3 u64 fields (values fit).
    fn serializeMeta(self: *VexLedger, slot: u64, m: SlotMeta) ![]u8 {
        const v3: agave_wire.SlotMetaV3 = .{
            .slot = slot,
            .consumed = m.consumed,
            .received = m.received,
            .first_shred_timestamp = m.first_shred_timestamp,
            .last_index = if (m.last_index) |li| @as(u64, li) else null,
            .parent_slot = m.parent_slot,
            .next_slots = m.next_slots,
            .connected_flags = m.connected_flags,
            .completed_data_indexes = m.completed_data_indexes,
            .parent_block_id = m.parent_block_id,
            .replay_fec_set_index = m.replay_fec_set_index,
        };
        return v3.encode(self.allocator);
    }

    /// Deserialize a SlotMeta from a byte-exact `SlotMetaV3` payload. The two owned
    /// slices (completed_data_indexes, next_slots) are allocated by the wire decoder
    /// and OWNERSHIP TRANSFERS to the returned SlotMeta (freed via freeMetaOwned).
    /// Errors (framing mismatch / truncation) propagate — recovery best-effort-skips.
    fn deserializeMeta(self: *VexLedger, payload: []const u8) !SlotMeta {
        const v3 = try agave_wire.SlotMetaV3.decode(self.allocator, payload);
        // v3 owns next_slots + completed_data_indexes; transfer them out as-is.
        return .{
            .parent_slot = v3.parent_slot,
            .received = @intCast(v3.received),
            .consumed = @intCast(v3.consumed),
            .last_index = if (v3.last_index) |li| @as(u32, @intCast(li)) else null,
            .connected_flags = v3.connected_flags,
            .first_shred_timestamp = v3.first_shred_timestamp,
            .completed_data_indexes = v3.completed_data_indexes,
            .next_slots = v3.next_slots,
            .parent_block_id = v3.parent_block_id,
            .replay_fec_set_index = v3.replay_fec_set_index,
        };
    }

    /// Store a deep copy of `m` for `slot`, freeing any previously-stored meta,
    /// and record `seg_seq` as the backing segment of this meta record (for
    /// prune-accurate eviction). Deep-copies BOTH owned slices.
    fn storeMeta(self: *VexLedger, slot: u64, m: SlotMeta, seg_seq: u32) !void {
        const owned_indexes = try self.allocator.dupe(u32, m.completed_data_indexes);
        errdefer self.allocator.free(owned_indexes);
        const owned_next = try self.allocator.dupe(u64, m.next_slots);
        errdefer self.allocator.free(owned_next);

        var stored = m;
        stored.completed_data_indexes = owned_indexes;
        stored.next_slots = owned_next;

        // Record the backing seq first; if this fails we haven't mutated slot_meta
        // yet (errdefers free the dupes). meta_seq + slot_meta stay in lockstep so
        // pruning drops the meta exactly when its segment is gone.
        try self.meta_seq.put(slot, seg_seq);

        if (try self.slot_meta.fetchPut(slot, stored)) |old| {
            self.freeMetaOwned(old.value);
        }
    }

    /// Free a SlotMeta's owned slices (completed_data_indexes + next_slots).
    fn freeMetaOwned(self: *VexLedger, m: SlotMeta) void {
        if (m.completed_data_indexes.len != 0) self.allocator.free(m.completed_data_indexes);
        if (m.next_slots.len != 0) self.allocator.free(m.next_slots);
    }

    /// Free every owned `bytes` slice in a StoredBytes-valued map, then the map.
    /// Generic over the key type (SigSlotKey for tx_status/memos, u64 for rewards).
    fn freeBytesMap(self: *VexLedger, map: anytype) void {
        var it = map.valueIterator();
        while (it.next()) |v| self.allocator.free(v.bytes);
        map.deinit();
    }

    // ── Per-slot index lists (G4: O(k) enumeration, no O(n) scan) ────────────
    // Generic over a `slot -> sorted-on-read index list` map; used for BOTH the
    // data-shred index (`slot_shreds`) and the coding-shred index (`slot_codes`).

    const SlotListMap = std.AutoHashMap(u64, std.ArrayListUnmanaged(u32));

    /// Record that `index` exists for `slot` in `map` (caller guarantees it is
    /// NEW so the list stays dup-free). Creates the per-slot list on first sight.
    fn addToSlotList(self: *VexLedger, map: *SlotListMap, slot: u64, index: u32) !void {
        const gop = try map.getOrPut(slot);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(self.allocator, index);
    }

    /// Remove `index` from `slot`'s list in `map` (prune, when the backing segment
    /// is unlinked). Frees + drops the slot entry when empty.
    fn removeFromSlotList(self: *VexLedger, map: *SlotListMap, slot: u64, index: u32) void {
        const lst = map.getPtr(slot) orelse return;
        for (lst.items, 0..) |v, i| {
            if (v == index) {
                _ = lst.swapRemove(i);
                break;
            }
        }
        if (lst.items.len == 0) {
            lst.deinit(self.allocator);
            _ = map.remove(slot);
        }
    }

    /// Free every per-slot list in `map`, then the map.
    fn freeSlotList(self: *VexLedger, map: *SlotListMap) void {
        var it = map.valueIterator();
        while (it.next()) |lst| lst.deinit(self.allocator);
        map.deinit();
    }
};

/// pread exactly `buf.len` bytes from `file` starting at `offset`, looping over
/// short reads. Returns CorruptRecord if EOF is hit before the buffer is full
/// (callers only invoke this for ranges they've already bounds-checked against
/// the file size, so this signals genuine corruption).
fn preadExact(file: std.fs.File, buf: []u8, offset: u64) !void {
    var done: usize = 0;
    while (done < buf.len) {
        const n = try file.pread(buf[done..], offset + done);
        if (n == 0) return VexLedgerError.CorruptRecord;
        done += n;
    }
}
