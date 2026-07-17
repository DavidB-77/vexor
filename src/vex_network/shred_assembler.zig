//! Vexor shred receive-side assembler (SPLIT module 57, from `shred.zig`).
//!
//! `ShredAssembler` + its nested `SlotAssembly` zero-alloc slab: per-slot
//! shred collection (zero-copy UMEM frame path + heap-copy fallback path),
//! O(1) dedup/completeness tracking, the stale-slot sweeper, FEC-resolver
//! wiring (data+coding shred admission, recovered-shred pull-in), the
//! zero-copy frame-overwrite drop gate (carrier 420258409 fix), SIMD-0340
//! chain observation, and the last-FEC-set / block_id derivation family
//! (`checkLastFecSet[32]`, `lastShredMerkleRoot32`, `firstShredChainedMerkleRoot`).
//! This is the "one dominant 82%-of-file struct" half of the original
//! monolith (contrast with `shred_parse.zig`'s two independent small
//! structs) — but unlike `tvu.zig`/`bank.zig`, `ShredAssembler` itself
//! does not reach across the split boundary in a way that blocks a clean
//! move: it only *consumes* `shred_parse.zig`'s `Shred`/`parseShred`, never
//! the reverse. See REBUILD-LEDGER.md module 57 for the full split
//! rationale, fidelity proof, and per-file md5s.
const std = @import("std");
const fec_resolver = @import("fec_resolver.zig");
const af_xdp = @import("af_xdp/socket.zig");
const bmtree = @import("bmtree.zig");
const shred_parse = @import("shred_parse.zig");
const Shred = shred_parse.Shred;
const parseShred = shred_parse.parseShred;

/// Re-export for consumers (moved here from the pre-split shred.zig header —
/// only ShredAssembler/SlotAssembly reference these two types).
pub const UmemFrameRef = af_xdp.UmemFrameRef;
pub const UmemFrameManager = af_xdp.UmemFrameManager;

pub const ShredAssembler = struct {
    allocator: std.mem.Allocator,
    slots: std.AutoHashMap(u64, *SlotAssembly),
    fec_resolver: fec_resolver.FecResolver,
    highest_completed_slot: std.atomic.Value(u64),
    mutex: std.Thread.Mutex,
    /// d28ll (2026-05-12): SIMD-0340 chain-tracker. Resurrected from
    /// team-b/vex-037-simd-0340-wireup (April 17 — never merged to master).
    /// Per-slot intra/inter chain validation at TVU shred-INSERT time.
    /// See `src/vex_network/slot_chain_tracker.zig` for full library.
    chain_tracker: @import("slot_chain_tracker.zig").SlotChainTracker,
    /// Optional frame manager for releasing zero-copy UMEM frames on slot cleanup.
    /// Set by TVU after initialization via setFrameManager().
    frame_manager: ?*UmemFrameManager = null,
    /// Last time sweepStaleSlots() was called (nanoseconds)
    last_sweep_ns: u64 = 0,

    /// FIX 2026-07-07 (carrier 420258409): count of zero-copy UMEM frames
    /// dropped because the NIC recycled/overwrote the frame mid-processing
    /// (checksum mismatch between verify-time and copy-time, "[FRAME-OVERWRITE]").
    /// See insertFrameWithFec — these frames are NEVER fed to fec_resolver.addShred
    /// or the data-shred assembly; the (slot,idx) hole self-heals via repair/turbine.
    frame_overwrite_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// d27r (2026-05-11): catchup-range ceiling. When set, any slot with
    /// `slot_key < catchup_ceiling` is treated as repair-territory by the
    /// stale-slot sweeper regardless of distance from highest_completed_slot.
    /// Set by TVU to `turbine_slot0` once first turbine shred is observed —
    /// every slot in `(snapshot_root, turbine_slot0]` is historical and being
    /// repaired in bursts; they MUST get the full 5-minute REPAIR_SLOT_TIMEOUT_NS
    /// and not the 30-second LIVE_SLOT_TIMEOUT_NS that the head-distance
    /// classifier would otherwise apply to them.
    ///
    /// Root cause: once even one catchup slot completes, highest_completed_slot
    /// jumps to that slot. Slots immediately above snapshot_root (e.g., root+1)
    /// land within LIVE_SLOT_WINDOW (1000) of the completed slot, get classified
    /// "live", and inherit a 30-second timeout. A near-root slot whose only
    /// shred is the single HighestWindowIndex response from seed-burst has
    /// `last_updated_ns` stamped at HWI receipt time; if WindowIndex fill-in
    /// takes >30s (typical during gossip warm-up), the sweeper reaps it,
    /// the chain stalls one slot above root forever.
    catchup_ceiling: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // ═══════════════════════════════════════════════════════════════════════
    // SlotAssembly: Zero-Alloc Slab with Dual-Path Storage
    // ═══════════════════════════════════════════════════════════════════════

    pub const SlotAssembly = struct {
        allocator: std.mem.Allocator,
        slot: u64,

        // ── Zero-Copy Path: UMEM frame references (no allocation, no copy) ──
        // 2026-05-26: bumped 2048 → 32768 to match Agave MAX_DATA_SHREDS_PER_SLOT
        // and Firedancer FD_SHRED_BLK_MAX. Smaller caused late-index shreds to be
        // silently dropped → slot never completes → catchup wedge (root cause of
        // the 2026-05-26 4999-slot-gap wedge; LOST during baseline restart from f2a4507).
        frames: [32768]?UmemFrameRef =
            [_]?UmemFrameRef{null} ** 32768,

        // ── Copy Path: heap-allocated payloads (kernel socket, FEC recovery, FramePressure) ──
        copied: [32768]?[]u8 =
            [_]?[]u8{null} ** 32768,

        // ── O(1) dedup bitmap (replaces HashMap.contains()) ──
        received: std.StaticBitSet(32768) =
            std.StaticBitSet(32768).initEmpty(),

        /// Provenance bitmap: set for a data-shred index inserted via the
        /// FEC-completion pull-in path (ShredAssembler.insert/insertBatch/
        /// insertFrameWithFec step 3 — the loop that pulls `set.data_shreds[i]`
        /// out of a just-completed FecSet) rather than the direct per-shred
        /// insert path (step 2, driven straight off a received network shred).
        /// In practice this is (almost) exactly "was Reed-Solomon-recovered":
        /// a data shred that arrived directly is inserted at step 2 as soon as
        /// it's received, so by the time its FEC set later completes, step 3's
        /// `!rec_assembly.contains(global_idx)` guard skips it — the pull-in
        /// loop only ends up inserting indices nothing else has claimed, i.e.
        /// the ones Reed-Solomon actually reconstructed (fec_resolver.zig
        /// recoverWithSigMethod). Diagnostics-only: does NOT gate anything (see
        /// getAssembledDataWithBoundaries — incident-422359406 postmortem,
        /// [[incident-422359406-fec-datacomplete-truncation-2026-07-16]]).
        recovered: std.StaticBitSet(32768) =
            std.StaticBitSet(32768).initEmpty(),

        received_count: u32 = 0,
        /// Highest data-shred index received so far (O(1) tracking, Firedancer-style)
        highest_received_index: u32 = 0,
        last_index: ?u32 = null,
        is_complete: bool = false,

        /// Timestamp of last insert (nanoseconds) — used by stale slot sweeper
        last_updated_ns: u64 = 0,

        /// @prov:shred.max-per-slot — 32,768. Anything smaller silently drops
        /// late-arriving shreds with index ≥ N → slot never completes → catchup wedge.
        pub const MAX_SHREDS_PER_SLOT: u32 = 32768;

        pub fn init(allocator: std.mem.Allocator, slot: u64) SlotAssembly {
            return .{
                .allocator = allocator,
                .slot = slot,
                .last_updated_ns = @intCast(std.time.nanoTimestamp()),
            };
        }

        /// Deinit: free all copied payloads. Does NOT release UMEM frames —
        /// caller must call deinitWithFrameManager() for that.
        pub fn deinit(self: *SlotAssembly) void {
            for (&self.copied) |*c| {
                if (c.*) |payload| {
                    self.allocator.free(payload);
                    c.* = null;
                }
            }
            self.allocator.destroy(self);
        }

        /// Deinit with UMEM frame release — releases all held frames back to
        /// the Fill Ring via the frame manager, then frees copied payloads.
        pub fn deinitWithFrameManager(self: *SlotAssembly, fm: *UmemFrameManager) void {
            for (&self.frames) |*f| {
                if (f.*) |ref| {
                    fm.release(ref.frame_addr);
                    f.* = null;
                }
            }
            self.deinit();
        }

        /// Convert all held UMEM frames into heap-allocated copies, then
        /// release the UMEM frames back to the Fill Ring. The `received`
        /// bitmap stays intact, and `getPayload(idx)` continues to return the
        /// shred payload (from `copied[idx]` instead of `frames[idx]`).
        ///
        /// AF_XDP CATCHUP DEADLOCK FIX (2026-05-26): the original design left
        /// UMEM frames held in `self.frames[]` after `getAssembledDataWithBoundaries`
        /// copied the slot's data into the caller's heap buffer. During catchup,
        /// ~50 deferred slots × ~600 frames each exhausts the 32K-frame UMEM
        /// pool → fill ring drains → kernel drops every incoming shred → can't
        /// bridge CHAIN-DEFER → permanent wedge.
        ///
        /// Why heap-copy instead of just release? Downstream consumers
        /// (`checkLastFecSet32`, `firstShredChainedMerkleRoot`, used by
        /// replay_stage.zig:2206-2222 for SIMD-0340 enforcement) call
        /// `getPayload(idx)` AFTER `getAssembledDataWithBoundaries` returns.
        /// They need the original shred bytes (headers + payload) to derive
        /// merkle roots. Releasing the frames AND falling through to
        /// `copied[idx]` keeps these consumers transparent.
        ///
        /// Memory cost: ~600 shreds × ~1200 bytes ≈ 720KB heap per slot
        /// (vs the same data held in UMEM previously). At 50 deferred slots
        /// = 36MB heap. Negligible vs 33GB validator RSS. The benefit is the
        /// 32K-frame UMEM pool now gets refilled, breaking the fill-ring
        /// starvation.
        ///
        /// Threading: caller must hold `ShredAssembler.mutex` to prevent
        /// concurrent insertFrame races. `getAssembledDataWithBoundaries`
        /// already holds it.
        ///
        /// Errors: returns OutOfMemory if any copy allocation fails. On
        /// failure, the SlotAssembly state is left as-is (no partial release).
        pub fn convertFramesToCopiesAndRelease(
            self: *SlotAssembly,
            fm: *UmemFrameManager,
        ) !usize {
            // Two-pass: first allocate all copies (so we can fail cleanly
            // without partial release); then release frames.
            var copies_to_install: [MAX_SHREDS_PER_SLOT]?[]u8 = [_]?[]u8{null} ** MAX_SHREDS_PER_SLOT;
            errdefer {
                // On failure, free anything we already allocated for THIS call
                for (&copies_to_install) |*c| {
                    if (c.*) |buf| self.allocator.free(buf);
                }
            }
            for (&self.frames, 0..) |*f, i| {
                if (f.*) |ref| {
                    // Skip if a copy already exists for this index (don't
                    // double-allocate). The frame will still be released.
                    if (self.copied[i] != null) continue;
                    const buf = try self.allocator.alloc(u8, ref.len);
                    @memcpy(buf, ref.data[0..ref.len]);
                    copies_to_install[i] = buf;
                }
            }

            // Install copies + release frames. From here on the operation
            // is infallible (no allocations).
            var released: usize = 0;
            for (&self.frames, 0..) |*f, i| {
                if (f.*) |ref| {
                    if (copies_to_install[i]) |buf| {
                        self.copied[i] = buf;
                        copies_to_install[i] = null; // prevent errdefer free
                    }
                    fm.release(ref.frame_addr);
                    f.* = null;
                    released += 1;
                }
            }
            return released;
        }

        /// Check if a shred index has been received (O(1) bitmap lookup)
        pub fn contains(self: *const SlotAssembly, index: u32) bool {
            if (index >= MAX_SHREDS_PER_SLOT) return false;
            return self.received.isSet(index);
        }

        /// Mark index as inserted via the FEC-completion pull-in path (see
        /// `recovered` field doc). Called by ShredAssembler AFTER a successful
        /// (non-duplicate, non-error) pull-in insert — never from the direct
        /// network insert path. Diagnostics-only.
        pub fn markRecovered(self: *SlotAssembly, index: u32) void {
            if (index >= MAX_SHREDS_PER_SLOT) return;
            self.recovered.set(index);
        }

        /// Get shred count (O(1) — no iteration needed)
        pub fn count(self: *const SlotAssembly) u32 {
            return self.received_count;
        }

        /// Get raw payload for a shred index (prefers UMEM frame, falls back to copy).
        /// Returns null if the shred hasn't been received.
        pub fn getPayload(self: *const SlotAssembly, index: u32) ?[]const u8 {
            if (index >= MAX_SHREDS_PER_SLOT) return null;
            if (!self.received.isSet(index)) return null;

            // Prefer zero-copy frame data
            if (self.frames[index]) |ref| {
                return ref.data[0..ref.len];
            }
            // Fallback to copied data
            if (self.copied[index]) |payload| {
                return payload;
            }
            return null;
        }

        /// Insert via copy path (fallback: kernel socket, FEC recovery, FramePressure)
        pub fn insert(self: *SlotAssembly, index: u32, payload: []const u8, is_last: bool) !bool {
            if (self.is_complete) return false;
            if (index >= MAX_SHREDS_PER_SLOT) return false;
            if (self.received.isSet(index)) return false;

            const copy = try self.allocator.alloc(u8, payload.len);
            @memcpy(copy, payload);
            self.copied[index] = copy;
            self.received.set(index);
            self.received_count += 1;
            if (index > self.highest_received_index) self.highest_received_index = index;
            // Update timestamp every 64 inserts to keep sweeper happy (not every insert)
            if (self.received_count & 63 == 0) self.last_updated_ns = @intCast(std.time.nanoTimestamp());

            return self.handleLastAndComplete(index, is_last);
        }

        /// Insert via zero-copy path (UMEM frame reference — no allocation, no copy).
        /// `fm` (the UMEM frame manager) MUST be passed so a REJECTED frame is
        /// released back to the fill ring. 2026-05-24 LEAK FIX: previously the
        /// three reject branches returned without releasing — but a rejected
        /// frame is never stored in self.frames[], so deinitWithFrameManager
        /// can never release it either → the UMEM frame leaked permanently.
        /// Duplicate-index shreds (common: turbine retransmits + repair) leaked
        /// one frame each, draining the AF_XDP fill ring over ~30 min →
        /// rx_xsk_buff_alloc_err returned. Mirrors insertOwned's free-on-reject.
        pub fn insertFrame(self: *SlotAssembly, index: u32, frame: UmemFrameRef, is_last: bool, fm: ?*UmemFrameManager) bool {
            if (self.is_complete) {
                if (fm) |m| m.release(frame.frame_addr);
                return false;
            }
            if (index >= MAX_SHREDS_PER_SLOT) {
                if (fm) |m| m.release(frame.frame_addr);
                return false;
            }
            if (self.received.isSet(index)) {
                if (fm) |m| m.release(frame.frame_addr); // duplicate — release or it leaks
                return false;
            }

            self.frames[index] = frame;
            self.received.set(index);
            self.received_count += 1;
            if (index > self.highest_received_index) self.highest_received_index = index;
            if (self.received_count & 63 == 0) self.last_updated_ns = @intCast(std.time.nanoTimestamp());

            return self.handleLastAndComplete(index, is_last);
        }

        /// Insert via ownership transfer (zero-copy handoff from FEC recovery).
        /// Caller transfers ownership of `owned_payload` — it will be freed
        /// by SlotAssembly.deinit(). No memcpy, no allocation.
        ///
        /// Use this instead of insert() when you already have a heap-allocated
        /// buffer (e.g., from FEC reconstruction) to avoid redundant copying.
        pub fn insertOwned(self: *SlotAssembly, index: u32, owned_payload: []u8, is_last: bool) bool {
            if (self.is_complete) {
                self.allocator.free(owned_payload);
                return false;
            }
            if (index >= MAX_SHREDS_PER_SLOT) {
                self.allocator.free(owned_payload);
                return false;
            }
            if (self.received.isSet(index)) {
                self.allocator.free(owned_payload); // Duplicate — free the caller's buffer
                return false;
            }

            self.copied[index] = owned_payload; // Transfer ownership — no copy
            self.received.set(index);
            self.received_count += 1;
            if (index > self.highest_received_index) self.highest_received_index = index;

            return self.handleLastAndComplete(index, is_last);
        }

        /// Shared logic for last-index tracking and completeness check
        /// Firedancer-inspired: O(1) highest tracking instead of O(N) linear scan
        fn handleLastAndComplete(self: *SlotAssembly, index: u32, is_last: bool) bool {
            // FEC-boundary guard (DEFENSE-IN-DEPTH layer) — same invariant as the
            // primary Agave/FD ingress DISCARD in verify_tile.zig
            // ([FEC-BOUNDARY-DISCARD], port of Agave filter.rs:344 /
            // FD fd_fec_resolver.c:544). In the merkle shred format EVERY FEC set,
            // including the final one, holds exactly DATA_SHREDS_PER_FEC_BLOCK (=32)
            // data shreds (producer pads the remainder — Agave merkle.rs:1225, FD
            // fd_shredder.c:169), so the true last data shred is ALWAYS at
            // fec_set_index+31, i.e. (index+1) % 32 == 0. The primary filter
            // discards an off-boundary LAST_IN_SLOT at network ingress (before the
            // assembler/FEC), so a network shred can never reach here off-boundary.
            // This chokepoint remains as the safety net for the ONE path that
            // bypasses ingress: FEC-RECOVERED data shreds (insertOwned), whose
            // last-flag is reconstructed rather than ingress-filtered. Here we keep
            // the recovered shred's DATA (received_count already counted it in the
            // caller) but WITHHOLD the off-boundary last-flag so the slot stays
            // incomplete and repair/turbine fetch the true tail — never the 61-tick
            // premature freeze that dead-slotted 413204194. Ref:
            // ROOT-CAUSE-FEC-BOUNDARY-LAST-SHRED-2026-06-04.md.
            const on_fec_boundary = (index + 1) % DATA_SHREDS_PER_FEC_BLOCK == 0;
            if (is_last and !on_fec_boundary) {
                // Positive-assertion instrumentation (advisor): rare (~1/hr live);
                // the per-index dedup bitmap (insert/insertFrame/insertOwned reject
                // duplicate indices before this chokepoint) bounds this to once per
                // unique index — no firehose. Distinct tag from the ingress
                // [FEC-BOUNDARY-DISCARD] so a soak can tell which layer fired (this
                // one firing ⇒ the recovery path produced an off-boundary last).
                std.log.warn(
                    "[FEC-BOUNDARY-GUARD] slot {d}: withholding off-boundary LAST_IN_SLOT at index {d} ((index+1)%32={d}≠0; canonical last at fec_set {d}+31); recovery-path safety net, slot stays incomplete, repair fetches tail",
                    .{ self.slot, index, (index + 1) % DATA_SHREDS_PER_FEC_BLOCK, (index / DATA_SHREDS_PER_FEC_BLOCK) * DATA_SHREDS_PER_FEC_BLOCK },
                );
            }
            if (is_last and on_fec_boundary) {
                // Defensive: If we already have shreds with indices HIGHER than this "last" index,
                // it's a spurious "last" bit (equivocation or reordering).
                // O(1) check using incrementally-tracked highest_received_index
                if (index < self.highest_received_index) {
                    // Spurious LAST bit — we already have higher-indexed shreds
                    return false;
                } else {
                    if (self.last_index) |prev_last| {
                        if (prev_last != index) {
                            std.log.warn("[Assembler] Slot {d} LAST_INDEX changed from {d} to {d}!", .{ self.slot, prev_last, index });
                        }
                    }
                    self.last_index = index;
                    // Update timestamp on LAST shred event (rare — once per slot)
                    // Keeps sweeper alive without per-insert syscall overhead
                    self.last_updated_ns = @intCast(std.time.nanoTimestamp());
                }
            }

            // Check if complete: ALL data shreds 0..=last_index received
            // (Agave Blockstore::is_full — consecutive from 0 through last).
            //
            // Incident 421935259 (2026-07-14): the old predicate was COUNT-based
            // (`received_count >= last+1`). received_count also counts shreds with
            // index > last_index (inserted before the last-flag arrived — nothing
            // rejects them), so shreds ABOVE last masked HOLES BELOW it and a
            // truncated assembly was declared complete ([SLOT-COMPLETED via
            // idx=345], 30/64 ticks) and frozen+voted. The contiguity check makes
            // hole-masked completion impossible; the slot stays incomplete and
            // repair fills the true holes. For a genuinely full slot every index
            // 0..=last is present, so this is behavior-identical — it can only
            // block FALSE completions, never delay a truly complete slot. Cost: the
            // scan runs only once count reaches last+1 (completion candidate).
            if (self.last_index) |last| {
                if (self.received_count >= last + 1 and self.allReceivedThrough(last)) {
                    self.is_complete = true;
                    return true;
                }
            }
            return false;
        }

        /// True iff every data-shred index 0..=last has been received (the
        /// Agave `is_full` contiguity invariant). O(last) bit tests, executed
        /// only on completion candidates (count >= last+1), never per-insert.
        fn allReceivedThrough(self: *const SlotAssembly, last: u32) bool {
            var i: u32 = 0;
            while (i <= last) : (i += 1) {
                if (!self.received.isSet(i)) return false;
            }
            return true;
        }

        /// @prov:shred.check-last-fec-set — d27mm (2026-05-11): verifies that
        /// the last `DATA_SHREDS_PER_FEC_BLOCK` (=32) data shreds of this slot
        /// all share ONE merkle root. If they do, the last FEC set is
        /// well-formed and the slot may be frozen; the shared merkle root
        /// becomes the bank's `block_id`. If they don't, OR if there are
        /// fewer than 32 shreds, OR if last_index is unknown, OR if any
        /// shred is missing/legacy, the slot is marked DEAD and freeze is
        /// skipped.
        pub const DATA_SHREDS_PER_FEC_BLOCK: u32 = 32;
        pub const LastFecSetResult = union(enum) {
            ok: [bmtree.MERKLE_NODE_SIZE]u8, // merkle_root = block_id
            incomplete_final_fec_set,
            unknown_last_index,
            missing_shred: u32,
            legacy_shred: u32,
            missing_merkle_root: u32,
        };

        /// SIMD-0340 (d28ll): 32-byte variant of LastFecSetResult.
        /// @prov:shred.check-last-fec-set32 — the `ok` value is the canonical
        /// 32-byte `Hash` block_id.
        pub const LastFecSetResult32 = union(enum) {
            ok: [32]u8,
            incomplete_final_fec_set,
            unknown_last_index,
            missing_shred: u32,
            legacy_shred: u32,
            missing_merkle_root: u32,
        };

        /// @prov:shred.check-last-fec-set32 — SIMD-0340 (d28ll), 32-byte
        /// canonical variant of checkLastFecSet.
        /// Same gating logic — last DATA_SHREDS_PER_FEC_BLOCK shreds must
        /// share one merkle root — but uses `merkleRoot32()` so the returned
        /// block_id matches the byte width expected for
        /// `check_chained_block_id`. Required for the SIMD-0340 fork-orphan
        /// gate: child slots compare their stored 32-byte chained_merkle_root
        /// against the parent bank's 32-byte block_id, and a truncated
        /// 20-byte comparison would let arbitrary orphan forks slip through.
        pub fn checkLastFecSet32(self: *const SlotAssembly) LastFecSetResult32 {
            const last = self.last_index orelse return .unknown_last_index;
            const MINIMUM_INDEX: u32 = DATA_SHREDS_PER_FEC_BLOCK - 1;
            if (last < MINIMUM_INDEX) return .incomplete_final_fec_set;
            const start: u32 = last - MINIMUM_INDEX;

            var first_pair: ?struct { root: [32]u8, resigned: bool } = null;
            var idx: u32 = start;
            while (idx <= last) : (idx += 1) {
                const payload = self.getPayload(idx) orelse return .{ .missing_shred = idx };
                const sh = parseShred(payload) catch return .{ .missing_shred = idx };
                if (!sh.common.variant.is_merkle) return .{ .legacy_shred = idx };
                const root = sh.merkleRoot32() orelse return .{ .missing_merkle_root = idx };
                const resigned = sh.common.variant.resigned;
                if (first_pair) |fp| {
                    if (!std.mem.eql(u8, &fp.root, &root) or fp.resigned != resigned) {
                        return .incomplete_final_fec_set;
                    }
                } else {
                    first_pair = .{ .root = root, .resigned = resigned };
                }
            }
            return .{ .ok = first_pair.?.root };
        }

        /// @prov:shred.block-id-v41 — v4.1 canonical block_id: the merkle
        /// root of the SINGLE last data shred (meta.last_index). v4.1 DELETED
        /// the 4.0 `check_last_fec_set` 32-shred completeness gate (verified:
        /// zero hits for check_last_fec_set / IncompleteFinalFecSet in the 4.1
        /// source), and Firedancer never had a replay-time completeness gate.
        /// That 4.0 gate false-fired on legal blocks whose FINAL FEC set has
        /// fewer than 32 data shreds: "the last 32 shreds by index" then span
        /// two FEC sets with different merkle roots → spurious
        /// `incomplete_final_fec_set`. Use this to derive block_id exactly as
        /// 4.1 does. Returns null when the slot / last shred / merkle root is
        /// unavailable (== 4.1 Ok(None)).
        pub fn lastShredMerkleRoot32(self: *const SlotAssembly) ?[32]u8 {
            const last = self.last_index orelse return null;
            const payload = self.getPayload(last) orelse return null;
            const sh = parseShred(payload) catch return null;
            return sh.merkleRoot32();
        }

        /// @prov:shred.chained-merkle-root — SIMD-0340 (d28ll): read the
        /// 32-byte chained_merkle_root from this slot's first data shred
        /// (index 0). The leader populated it from the parent slot's last
        /// shred merkle_root; for a non-orphan slot it MUST equal the parent
        /// bank's block_id.
        pub fn firstShredChainedMerkleRoot(self: *const SlotAssembly) ?[32]u8 {
            const payload = self.getPayload(0) orelse return null;
            const sh = parseShred(payload) catch return null;
            return sh.chainedMerkleRoot();
        }

        pub fn checkLastFecSet(self: *const SlotAssembly) LastFecSetResult {
            const last = self.last_index orelse return .unknown_last_index;
            const MINIMUM_INDEX: u32 = DATA_SHREDS_PER_FEC_BLOCK - 1; // 31
            if (last < MINIMUM_INDEX) return .incomplete_final_fec_set;
            const start: u32 = last - MINIMUM_INDEX;

            var first_pair: ?struct { root: [bmtree.MERKLE_NODE_SIZE]u8, resigned: bool } = null;
            var idx: u32 = start;
            while (idx <= last) : (idx += 1) {
                const payload = self.getPayload(idx) orelse return .{ .missing_shred = idx };
                const sh = parseShred(payload) catch return .{ .missing_shred = idx };
                if (!sh.common.variant.is_merkle) return .{ .legacy_shred = idx };
                const root = sh.merkleRoot() orelse return .{ .missing_merkle_root = idx };
                const resigned = sh.common.variant.resigned;
                if (first_pair) |fp| {
                    if (!std.mem.eql(u8, &fp.root, &root) or fp.resigned != resigned) {
                        // Two distinct (merkle_root, resigned) pairs after dedup
                        // — Agave returns `last_fec_set_merkle_root: None` ⇒
                        // BlockstoreProcessorError::IncompleteFinalFecSet.
                        return .incomplete_final_fec_set;
                    }
                } else {
                    first_pair = .{ .root = root, .resigned = resigned };
                }
            }
            return .{ .ok = first_pair.?.root };
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Initialization
    // ═══════════════════════════════════════════════════════════════════════

    /// Accessor for the FEC resolver (used to wire DuplicateShred detection ->
    /// gossip push). Returns a stable pointer (the resolver is an inline field of
    /// the heap-allocated assembler, valid for the assembler's lifetime).
    pub fn getFecResolver(self: *ShredAssembler) *fec_resolver.FecResolver {
        return &self.fec_resolver;
    }

    pub fn init(allocator: std.mem.Allocator) !*ShredAssembler {
        return try initWithShredVersion(allocator, 0);
    }

    pub fn initWithShredVersion(allocator: std.mem.Allocator, version: u16) !*ShredAssembler {
        // Default: Data-Only mode (FEC recovery disabled for stability)
        return try initWithConfig(allocator, version, false, false);
    }

    /// Initialize with FEC recovery enabled (use only after RS bugs are fixed)
    pub fn initWithFecRecovery(allocator: std.mem.Allocator, version: u16) !*ShredAssembler {
        return try initWithConfig(allocator, version, true, false);
    }

    /// Initialize with FEC recovery AND SIMD acceleration enabled
    pub fn initWithFecAndSimd(allocator: std.mem.Allocator, version: u16) !*ShredAssembler {
        return try initWithConfig(allocator, version, true, true);
    }

    fn initWithConfig(allocator: std.mem.Allocator, version: u16, enable_recovery: bool, enable_simd: bool) !*ShredAssembler {
        const self = try allocator.create(ShredAssembler);
        const fec = if (!enable_recovery)
            fec_resolver.FecResolver.initDataOnly(allocator, 100, version)
        else if (enable_simd)
            fec_resolver.FecResolver.initWithSimd(allocator, 100, version)
        else
            fec_resolver.FecResolver.init(allocator, 100, version);

        self.* = .{
            .allocator = allocator,
            .slots = std.AutoHashMap(u64, *SlotAssembly).init(allocator),
            .fec_resolver = fec,
            .highest_completed_slot = std.atomic.Value(u64).init(0),
            .mutex = .{},
            .chain_tracker = @import("slot_chain_tracker.zig").SlotChainTracker.init(allocator),
        };

        if (!enable_recovery) {
            std.log.info("[Assembler] Data-Only mode: FEC recovery DISABLED for stability", .{});
        } else if (enable_simd) {
            std.log.info("[Assembler] FEC recovery ENABLED with SIMD acceleration", .{});
        } else {
            std.log.info("[Assembler] FEC recovery ENABLED - Reed-Solomon erasure coding active", .{});
        }

        std.log.info("[Assembler] Zero-alloc slab: {d} shreds/slot capacity, 30s stale timeout", .{SlotAssembly.MAX_SHREDS_PER_SLOT});

        return self;
    }

    /// Set the UMEM frame manager (called by TVU after AcceleratedIO init).
    /// Required for proper UMEM frame release during slot cleanup and sweeping.
    pub fn setFrameManager(self: *ShredAssembler, fm: *UmemFrameManager) void {
        self.frame_manager = fm;
        std.log.info("[Assembler] UmemFrameManager attached — zero-copy frame release enabled", .{});
    }

    /// d27r: TVU calls this when turbine_slot0 is captured. Every slot
    /// strictly below the ceiling is repair-territory (5-min timeout).
    pub fn setCatchupCeiling(self: *ShredAssembler, ceiling: u64) void {
        self.catchup_ceiling.store(ceiling, .release);
        std.log.warn("[Assembler] catchup_ceiling set to {d} — slots below this get 5-min repair timeout", .{ceiling});
    }

    pub fn deinit(self: *ShredAssembler) void {
        // Scope the mutex to avoid use-after-free: unlock must happen BEFORE destroy.
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            var it = self.slots.valueIterator();
            while (it.next()) |assembly| {
                if (self.frame_manager) |fm| {
                    assembly.*.deinitWithFrameManager(fm);
                } else {
                    assembly.*.deinit();
                }
            }
            self.slots.deinit();
            self.fec_resolver.deinit();
            self.chain_tracker.deinit();
        }
        self.allocator.destroy(self);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Stale Slot Sweeper (Frame Leak Prevention)
    // ═══════════════════════════════════════════════════════════════════════

    /// Stale slot timeout for LIVE Turbine slots (close to head): 30 seconds
    const LIVE_SLOT_TIMEOUT_NS: u64 = 30 * std.time.ns_per_s;

    /// Stale slot timeout for REPAIR slots (far behind head): 5 minutes
    /// Repair slots arrive slowly via request/response — give them time.
    const REPAIR_SLOT_TIMEOUT_NS: u64 = 5 * 60 * std.time.ns_per_s;

    /// A slot is considered "live" (near the head) if it's within this many
    /// slots of the highest completed slot. Beyond this → repair territory.
    const LIVE_SLOT_WINDOW: u64 = 1000;

    /// Sweep interval: check for stale slots every 5 seconds
    const SWEEP_INTERVAL_NS: u64 = 5 * std.time.ns_per_s;

    /// Sweep stale slots: release all held UMEM frames and copied payloads
    /// for slots that haven't received any shreds within their timeout.
    ///
    /// Uses dual timeouts:
    ///   - Live slots (within 1000 of head): 30 seconds
    ///   - Repair slots (far behind head): 5 minutes
    ///
    /// Call this periodically from the TVU main loop.
    /// Returns the number of slots swept.
    pub fn sweepStaleSlots(self: *ShredAssembler) usize {
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());

        // Throttle: only sweep every 5 seconds
        if (now_ns < self.last_sweep_ns + SWEEP_INTERVAL_NS) return 0;
        self.last_sweep_ns = now_ns;

        self.mutex.lock();
        defer self.mutex.unlock();

        // Get the current head for live vs. repair classification
        const head_slot = self.highest_completed_slot.load(.seq_cst);
        // d27r: catchup-range slots (below turbine_slot0) are ALWAYS repair-territory
        // regardless of head distance — see catchup_ceiling field doc for rationale.
        const ceiling = self.catchup_ceiling.load(.acquire);

        // Collect stale slot keys (can't remove during iteration)
        var stale_keys = std.ArrayListUnmanaged(u64){};
        defer stale_keys.deinit(self.allocator);

        var it = self.slots.iterator();
        while (it.next()) |entry| {
            const assembly = entry.value_ptr.*;
            if (assembly.is_complete) continue; // Don't sweep completed slots (replay may need them)

            const age_ns = if (now_ns > assembly.last_updated_ns) now_ns - assembly.last_updated_ns else 0;
            const slot_key = entry.key_ptr.*;

            // Classify: is this a live Turbine slot or a historical repair slot?
            // CRITICAL: When head_slot == 0 (nothing completed yet), ALL slots are
            // repair slots and need the full 5-minute timeout. The old logic treated
            // them as 'live' (30s timeout) which killed them before they could assemble.
            // d27r: also force repair-territory for any slot below the catchup ceiling.
            const is_live = if (head_slot == 0)
                false // Nothing completed yet — everything is repair territory
            else if (ceiling > 0 and slot_key < ceiling)
                false // d27r: catchup-range slot — always 5-min timeout
            else
                (slot_key >= head_slot and slot_key - head_slot <= LIVE_SLOT_WINDOW) or
                    (head_slot > slot_key and head_slot - slot_key <= LIVE_SLOT_WINDOW);

            const timeout = if (is_live) LIVE_SLOT_TIMEOUT_NS else REPAIR_SLOT_TIMEOUT_NS;

            if (age_ns > timeout) {
                stale_keys.append(self.allocator, slot_key) catch continue;
            }
        }

        // Remove stale slots and release their resources
        for (stale_keys.items) |slot_key| {
            if (self.slots.fetchRemove(slot_key)) |removed| {
                const assembly = removed.value;
                const frame_count = assembly.received_count;

                // Classify for logging
                const is_live = (head_slot > 0) and
                    ((slot_key >= head_slot and slot_key - head_slot <= LIVE_SLOT_WINDOW) or
                        (head_slot > slot_key and head_slot - slot_key <= LIVE_SLOT_WINDOW));

                if (self.frame_manager) |fm| {
                    assembly.deinitWithFrameManager(fm);
                } else {
                    assembly.deinit();
                }

                std.log.info("[Sweeper] Cleaned {s} slot {d} ({d} shreds, {s})", .{
                    if (is_live) "live" else "repair",
                    slot_key,
                    frame_count,
                    if (self.frame_manager != null) "frames released" else "copies freed",
                });
            }
            self.fec_resolver.removeSlot(slot_key);
        }

        // FIX #76 (2026-05-28): unconditional periodic emission with framesHeld()
        // for the FIX #72/#75 leak investigation. Emits even when no slots swept
        // so we get a steady 5s cadence of UMEM pool state in production logs.
        // Looking for: framesHeld rising over time = leak; framesHeld flat near 0
        // while alloc_err climbs = leak is in kernel/XSK, not Vexor holders.
        const frames_held: u64 = if (self.frame_manager) |fm| fm.framesHeld() else 0;
        std.log.info("[Sweeper] swept={d} active={d} head={d} framesHeld={d} (FIX #76 diag)", .{
            stale_keys.items.len,
            self.slots.count(),
            head_slot,
            frames_held,
        });

        return stale_keys.items.len;
    }

    pub const InsertResult = enum {
        inserted,
        duplicate,
        completed_slot,
        /// FIX 2026-07-07: zero-copy frame failed the copy-time checksum
        /// re-check (NIC recycled the UMEM frame mid-processing) — dropped
        /// before touching the FEC resolver or the assembly, never inserted.
        dropped_frame_overwrite,
    };

    /// Receive a UMEM frame, COPY its data to heap, RELEASE the frame back to the
    /// fill ring. @prov:shred.copy-on-receive — same copy-on-receive /
    /// kernel-recvmmsg → heap pool pattern used upstream.
    ///
    /// FIX 2026-05-28 (Task #72 Option A'): previously this function HELD the
    /// UMEM frame in SlotAssembly.frames[idx] until the slot completed (via
    /// getAssembledDataWithBoundaries) or the sweeper timed out (30s live /
    /// 5min repair). At 150 slots/sec cluster pace, active SlotAssembly count
    /// grew to 1,760+ × ~20 frames each ≈ 35K held > 32K UMEM pool → fill ring
    /// starves → kernel drops 98% of packets → rx_xsk_buff_alloc_err climbed
    /// ~9K/sec sustained. Now mirrors Vexor's already-canonical coding-shred
    /// path at `tvu.zig:906-923` (which always copies + releases via
    /// fec_resolver.addShred + fm.release).
    ///
    /// Frame lifecycle: held for ~1 mutex-window (microseconds), not the
    /// full assembly window. Released on EVERY exit path (success, error,
    /// reject). Defense-in-depth `errdefer` covers any future error-return
    /// added before the copy completes.
    pub fn insertFrame(self: *ShredAssembler, slot_val: u64, index: u32, frame: UmemFrameRef, is_last: bool) !InsertResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        // FIX 2026-05-28 (Task #72): release the UMEM frame on EVERY exit path
        // (success, error, reject). The copy-on-receive pattern means we no
        // longer hold this frame past the copy below, so it's always safe to
        // return it to the fill ring after the function body completes.
        defer if (self.frame_manager) |m| m.release(frame.frame_addr);

        // Get or create SlotAssembly. The errdefer is no longer strictly
        // needed (the defer above already handles the error path) but kept
        // for explicit documentation that error paths must not leak.
        const gop = try self.slots.getOrPut(slot_val);
        if (!gop.found_existing) {
            std.log.info("[Assembler] New slot {d} discovered (copy-on-receive)", .{slot_val});
            const slot_asm = try self.allocator.create(SlotAssembly);
            slot_asm.* = SlotAssembly.init(self.allocator, slot_val);
            gop.value_ptr.* = slot_asm;
        }

        // FIX 2026-05-28 (Task #72): use SlotAssembly.insert (copy path)
        // instead of SlotAssembly.insertFrame (hold path). The legacy
        // insertFrame is preserved as dead code at line ~575 for future
        // reference but should not be called from production paths — it
        // recreates the leak class this fix addresses.
        const completed = try gop.value_ptr.*.insert(index, frame.data[0..frame.len], is_last);
        if (completed) {
            std.log.info("[Assembler] Slot {d} COMPLETED! (copy-on-receive)", .{slot_val});
            _ = self.highest_completed_slot.fetchMax(slot_val, .seq_cst);
            return .completed_slot;
        }
        return .inserted;
    }

    /// ── Net-tile Stage 2 (2026-06-14): AF_XDP zero-copy worker insert WITH FEC
    ///    + chain observation, fused under ONE assembler.mutex window. ──
    ///
    /// This REPLACES `insertFrame` on the AF_XDP zero-copy verify-worker path.
    /// Previously (Stage 1 and before) the recv thread did per-shred
    /// `fec_resolver.addShred` + `observeChainForShred` INLINE on core 4 (the
    /// residual recv-thread stall) and the worker called `insertFrame`
    /// (assembly-copy ONLY — no FEC, no chain). Stage 2 moves FEC + chain off the
    /// recv thread onto the 8 verify workers: recv now only RX + version-filter +
    /// submit-to-ring; this method does the FEC + recovered-shred pull + chain
    /// observation that recv used to do.
    ///
    /// It is a SEPARATE method (not a flag on `insert()`) so that `insert()` /
    /// `insertBatch()` — the kernel-UDP path, which NEVER observed the chain —
    /// stay byte-identical. The FEC body below is a faithful copy of `insert()`'s
    /// steps 1-3 (which already handle BOTH data and coding via the `!isData`
    /// guard); the only added behavior is the chain-observe block, which the
    /// kernel-UDP path must not have.
    ///
    /// Frame lifecycle: the UMEM frame is released on EVERY exit path within this
    /// one mutex window (the load-bearing Task #72 copy-on-receive release — hold
    /// the frame past the copy and the AF_XDP fill ring starves → the original
    /// collapse class). Data-shred bytes are copied into the assembly; coding
    /// bytes are copied into the FEC resolver (addShred) — never into data-shred
    /// index space (Bug A).
    ///
    /// `s` is the parsed shred (the worker already parsed it for sigverify); its
    /// own payload slice (`s.payload`) points into the frame and is consumed
    /// before the frame is released.
    pub fn insertFrameWithFec(self: *ShredAssembler, s: Shred, frame: UmemFrameRef, expected_cksum: u64) !InsertResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Task #72 release-on-every-exit: copy-on-receive means we never hold the
        // frame past the copies below, so it is always safe to return it to the
        // fill ring after the body completes. MUST stay on every path or AF_XDP
        // starves (rx_xsk_buff_alloc_err).
        defer if (self.frame_manager) |m| m.release(frame.frame_addr);

        const slot_val = s.slot();

        // DIAGNOSTIC (2026-06-15) + FIX (2026-07-07, carrier 420258409): zero-copy
        // frame OVERWRITE detector. The worker checksummed s.payload right after
        // parse/verify (expected_cksum). If the NIC recycled/overwrote this umem
        // frame mid-processing, the bytes about to be copied here differ from the
        // verified bytes → mismatch PROVES the race. expected_cksum==0 means
        // "skip" (non-zero-copy callers, e.g. the kernel-UDP path at tvu.zig:1672).
        //
        // Bug (pre-2026-07-07): on mismatch this only LOGGED and then FELL THROUGH
        // into fec_resolver.addShred + assembly.insert below, feeding the corrupted
        // (post-overwrite) bytes into live consensus state — under free_depth=0 UMEM
        // pool exhaustion this poisoned bank state and produced a bank_hash
        // divergence at carrier slot 420258409 (2 data=true hits at the carrier).
        //
        // Fix: DROP the frame outright — release it (the `defer` above already
        // does this on every exit path), do NOT call addShred/insert, and count
        // it. The (slot,idx) hole self-heals via turbine re-delivery / repair,
        // exactly like a dropped-on-sigverify-failure shred.
        if (expected_cksum != 0) {
            const now_cksum = std.hash.Wyhash.hash(0, s.payload);
            if (now_cksum != expected_cksum) {
                std.log.warn("[FRAME-OVERWRITE] slot={d} idx={d} fec={d} data={} verified_cksum={x} copy_cksum={x} len={d}", .{ slot_val, s.index(), s.fecSetIndex(), s.isData(), expected_cksum, now_cksum, s.payload.len });
                _ = self.frame_overwrite_dropped.fetchAdd(1, .monotonic);
                const dropped_total = self.frame_overwrite_dropped.load(.monotonic);
                std.log.warn("[FRAME-DROP] slot={d} idx={d} fec={d} data={} dropped_total={d}", .{ slot_val, s.index(), s.fecSetIndex(), s.isData(), dropped_total });
                return .dropped_frame_overwrite;
            }
        }

        // 1. Process in FEC resolver regardless of type (data AND coding).
        //    addShred is internally fec_mutex-guarded.
        const fr_res = self.fec_resolver.addShred(
            slot_val,
            s.index(),
            s.fecSetIndex(),
            s.isData(),
            s.payload,
            s.version(),
            s.numData(),
            s.numCoding(),
            s.codingPosition(),
        ) catch .err;

        // 2. Only DATA shreds enter the data-shred assembly. Coding shreds feed
        //    FEC (step 1) and trigger the recovery pull (step 3) on completion,
        //    but their payload must NEVER enter data-shred index space (Bug A).
        var completed = false;
        var result: InsertResult = .inserted;
        if (s.isData()) {
            const entry = try self.slots.getOrPut(slot_val);
            if (!entry.found_existing) {
                entry.value_ptr.* = try self.allocator.create(SlotAssembly);
                entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
            }
            const assembly = entry.value_ptr.*;

            if (assembly.contains(s.index())) {
                result = .duplicate;
            } else {
                completed = try assembly.insert(s.index(), s.payload, s.isLastInSlot());
            }
        }

        // 3. If FEC completed a set, pull recovered data shreds into assembly.
        if (fr_res == .complete) {
            const fsi = s.fecSetIndex();
            const key = fec_resolver.FecResolver.makeKey(slot_val, fsi);
            if (self.fec_resolver.active_sets.get(key)) |set| {
                const rec_entry = try self.slots.getOrPut(slot_val);
                if (!rec_entry.found_existing) {
                    rec_entry.value_ptr.* = try self.allocator.create(SlotAssembly);
                    rec_entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
                }
                const rec_assembly = rec_entry.value_ptr.*;

                var i: u16 = 0;
                while (i < set.data_shred_cnt) : (i += 1) {
                    if (set.data_received.isSet(i)) {
                        if (set.data_shreds[i]) |rec_shred| {
                            const global_idx = fsi + @as(u32, @intCast(i));
                            if (!rec_assembly.contains(global_idx)) {
                                if (Shred.fromPayload(rec_shred)) |temp_shred| {
                                    const is_rec_last = temp_shred.isLastInSlot();
                                    const rec_done = rec_assembly.insert(global_idx, rec_shred, is_rec_last) catch continue;
                                    // Provenance tag (diagnostics-only, see `recovered` field
                                    // doc) — only if the insert actually landed (not a race
                                    // loss against a concurrent path).
                                    if (rec_assembly.contains(global_idx)) rec_assembly.markRecovered(global_idx);
                                    if (rec_done) completed = true;
                                } else |_| continue;
                            }
                        }
                    }
                }
            }
        }

        // 4. CHAIN OBSERVATION (was tvu.zig observeChainForShred, recv-only). Same
        //    EXACT trigger gating as before: data shreds observe on fr_res ==
        //    .complete; coding shreds observe on fr_res == .complete AND the
        //    shred's chained variant (tvu.zig 1101 vs 1063). Observe off the
        //    COMPLETING shred (s), never the recovered ones — matches prior
        //    behavior so the recorded root is unchanged. num_data comes from the
        //    completed FEC set via getNumData (fec_mutex internal). observeAndRecord
        //    is chain_mutex-guarded (8 workers + replay race the tracker now).
        if (fr_res == .complete) {
            const do_observe = if (s.isData()) true else s.common.variant.chained;
            if (do_observe) self.observeChain(&s);
        }

        if (completed) {
            const assembly_completed = self.slots.get(slot_val).?;
            std.log.info("[Assembler] Slot {d} COMPLETED! (zc-worker-fec) Total shreds: {d}, Last index: {d}", .{
                slot_val, assembly_completed.count(), assembly_completed.last_index orelse 0,
            });
            _ = self.highest_completed_slot.fetchMax(slot_val, .seq_cst);
            return .completed_slot;
        }
        return result;
    }

    /// Chain observation for one shred (was TvuService.observeChainForShred at
    /// tvu.zig:1447). Called from `insertFrameWithFec` while holding
    /// `self.mutex` (assembler) on FEC-completion. Logic is unchanged; only the
    /// home moved (recv → ShredAssembler so the worker can call it) and the
    /// observe+record pair is now ONE chain_mutex critical section
    /// (observeAndRecord) instead of two calls.
    fn observeChain(self: *ShredAssembler, s: *const Shred) void {
        if (!s.isMerkle()) return;
        const this_root = s.merkleRoot32() orelse return;
        const chained_root = s.chainedMerkleRoot();
        const slot = s.slot();
        const fec_idx: u32 = s.fecSetIndex();
        // DIAGNOSTIC (2026-06-15): per-observe log so the equiv source is visible —
        // which shred (index, data vs coding) produced which root for a set.
        if (std.posix.getenv("VEX_CHAIN_TRACE") != null) {
            const tr = std.fmt.bytesToHex(this_root[0..8].*, .lower);
            std.log.warn("[OBSERVE] slot={d} fec={d} index={d} isData={} root={s}", .{ slot, fec_idx, s.index(), s.isData(), &tr });
        }
        // num_data sourced from the completed FEC set (a DATA shred's own
        // numData() is 0). Unknown (0) → tracker defers the forward check.
        const num_data: u32 = self.fec_resolver.getNumData(slot, fec_idx) orelse 0;

        const maybe_v = self.chain_tracker.observeAndRecord(
            slot,
            fec_idx,
            num_data,
            this_root,
            chained_root,
        ) catch |err| {
            std.log.warn("[SIMD-0340] tracker.observe alloc fail slot={d} err={s}", .{ slot, @errorName(err) });
            return;
        };
        if (maybe_v) |v| {
            const exp_hex = std.fmt.bytesToHex(v.expected_root, .lower);
            const obs_hex = std.fmt.bytesToHex(v.observed_root, .lower);
            std.log.warn(
                "[SIMD-0340 CHAIN-VIOLATION] slot={d} fec={d} kind={s} expected={s} observed={s}",
                .{ slot, fec_idx, @tagName(v.kind), &exp_hex, &obs_hex },
            );
        }
    }

    pub fn insert(self: *ShredAssembler, s: Shred) !InsertResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const slot_val = s.slot();
        const flags = if (s.payload.len > 85) s.payload[85] else 0;
        if (flags & 0xC0 != 0) {
            std.log.info("[Assembler] Shred slot={d} idx={d} flags=0x{x:0>2} (is_last={})", .{ slot_val, s.index(), flags, s.isLastInSlot() });
        }

        // 1. Process in FEC resolver regardless of type
        const fr_res = self.fec_resolver.addShred(
            slot_val,
            s.index(),
            s.fecSetIndex(),
            s.isData(),
            s.payload,
            s.version(),
            s.numData(),
            s.numCoding(),
            s.codingPosition(),
        ) catch .err;

        // FEC diagnostics: log recovery events (debug.print shows in journalctl)
        if (fr_res == .complete) {
            // Log every 10th FEC set completion to avoid spam
            const sets_done = self.fec_resolver.stats.sets_completed;
            if (sets_done % 10 == 1) {
                std.log.debug("[FEC-DIAG] Set COMPLETE: slot={d} fec={d} (total_sets={d} recovered={d} skipped={d})\n", .{
                    slot_val,
                    s.fecSetIndex(),
                    sets_done,
                    self.fec_resolver.stats.shreds_recovered,
                    self.fec_resolver.stats.recovery_skipped,
                });
            }
        }

        // 2. Only process data shreds for main assembly. Coding shreds
        //    participate in FEC reconstruction (step 1) and trigger the
        //    recovery pull at step 3 when the FEC set completes — but their
        //    own payload must NEVER be inserted into the data-shred index
        //    space (Bug A per vault/sessions/2026-04-14-shred-data-flow-trace.md:
        //    coding-shred bytes overwrote data-shred slots → silent slot loss).
        if (!s.isData() and fr_res != .complete) return .inserted;

        var completed = false;
        if (s.isData()) {
            const entry = try self.slots.getOrPut(slot_val);
            if (!entry.found_existing) {
                entry.value_ptr.* = try self.allocator.create(SlotAssembly);
                entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
            }
            const assembly = entry.value_ptr.*;

            if (assembly.contains(s.index())) {
                return .duplicate;
            }

            const is_last = s.isLastInSlot();
            if (is_last) {
                std.log.info("[Assembler] Received LAST shred for slot {d} at index {d}", .{ slot_val, s.index() });
            }

            completed = try assembly.insert(s.index(), s.payload, is_last);

            if (completed) {
                const assembly_completed = self.slots.get(slot_val).?;
                std.log.info("[Assembler] Slot {d} COMPLETED! Total shreds: {d}, Last index: {d}", .{ slot_val, assembly_completed.count(), assembly_completed.last_index.? });
                _ = self.highest_completed_slot.fetchMax(slot_val, .seq_cst);
                return .completed_slot;
            }
        }

        // 3. If FEC completed a set, pull recovered data shreds into assembly
        if (fr_res == .complete) {
            const fsi = s.fecSetIndex();
            const key = fec_resolver.FecResolver.makeKey(slot_val, fsi);
            if (self.fec_resolver.active_sets.get(key)) |set| {
                const rec_entry = try self.slots.getOrPut(slot_val);
                if (!rec_entry.found_existing) {
                    rec_entry.value_ptr.* = try self.allocator.create(SlotAssembly);
                    rec_entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
                }
                const rec_assembly = rec_entry.value_ptr.*;

                // Insert recovered shreds
                var i: u16 = 0;
                while (i < set.data_shred_cnt) : (i += 1) {
                    if (set.data_received.isSet(i)) {
                        if (set.data_shreds[i]) |rec_shred| {
                            const global_idx = fsi + @as(u32, @intCast(i));
                            if (!rec_assembly.contains(global_idx)) {
                                if (Shred.fromPayload(rec_shred)) |temp_shred| {
                                    const is_rec_last = temp_shred.isLastInSlot();
                                    const rec_done = rec_assembly.insert(global_idx, rec_shred, is_rec_last) catch continue;
                                    // Provenance tag (diagnostics-only, see `recovered` field doc).
                                    if (rec_assembly.contains(global_idx)) rec_assembly.markRecovered(global_idx);
                                    if (rec_done) completed = true;
                                } else |_| continue;
                            }
                        }
                    }
                }
            }
        }

        if (completed) {
            const assembly_completed = self.slots.get(slot_val).?;
            std.log.info("[Assembler] Slot {d} COMPLETED! Total shreds: {d}, Last index: {d}", .{ slot_val, assembly_completed.count(), assembly_completed.last_index.? });
            _ = self.highest_completed_slot.fetchMax(slot_val, .seq_cst);
            return .completed_slot;
        }

        if (!s.isData()) return .inserted; // Coding shreds count as "inserted" for flow control
        return .inserted;
    }

    /// @prov:shred.batch-insert — batch insert.
    /// Takes the lock ONCE and processes up to `shreds.len` shreds.
    /// Returns struct with counts of inserted, duplicates, and completed slots.
    /// This is dramatically faster than calling insert() per-shred because
    /// we avoid lock/unlock overhead per packet (critical at >100K shreds/sec).
    pub const BatchInsertResult = struct {
        inserted: usize = 0,
        duplicates: usize = 0,
        completed_slots: usize = 0,
        /// r49-B-rev-fix-2: slot numbers of completions in this batch, valid for
        /// indices [0..completed_slots). Caller iterates to dispatch onSlotCompleted.
        /// Cap at 32 — far above realistic per-batch completion count (typically 1-3).
        completed_slot_list: [32]u64 = undefined,
    };

    pub fn insertBatch(self: *ShredAssembler, shreds: []const Shred) BatchInsertResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = BatchInsertResult{};

        for (shreds) |s| {
            const slot_val = s.slot();

            // 1. Process in FEC resolver regardless of type
            const fr_res = self.fec_resolver.addShred(
                slot_val,
                s.index(),
                s.fecSetIndex(),
                s.isData(),
                s.payload,
                s.version(),
                s.numData(),
                s.numCoding(),
                s.codingPosition(),
            ) catch .err;

            // Log FEC completion periodically
            if (fr_res == .complete) {
                const sets_done = self.fec_resolver.stats.sets_completed;
                if (sets_done % 10 == 1) {
                    std.log.debug("[FEC-DIAG] Set COMPLETE: slot={d} fec={d} (total_sets={d} recovered={d} skipped={d})\n", .{
                        slot_val,
                        s.fecSetIndex(),
                        sets_done,
                        self.fec_resolver.stats.shreds_recovered,
                        self.fec_resolver.stats.recovery_skipped,
                    });
                }
            }

            // 2. Only process data shreds for main assembly. Coding shreds
            //    feed FEC reconstruction (step 1) and trigger the recovery
            //    pull at step 3, but their own payload must NEVER be inserted
            //    into data-shred index space (Bug A).
            if (!s.isData() and fr_res != .complete) {
                result.inserted += 1;
                continue;
            }

            var completed = false;
            if (s.isData()) {
                const entry = self.slots.getOrPut(slot_val) catch {
                    continue;
                };
                if (!entry.found_existing) {
                    entry.value_ptr.* = self.allocator.create(SlotAssembly) catch continue;
                    entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
                }
                const assembly = entry.value_ptr.*;

                if (assembly.contains(s.index())) {
                    result.duplicates += 1;
                    continue;
                }

                const is_last = s.isLastInSlot();
                if (is_last) {
                    std.log.info("[Assembler] Received LAST shred for slot {d} at index {d}", .{ slot_val, s.index() });
                }

                completed = assembly.insert(s.index(), s.payload, is_last) catch {
                    continue;
                };
            }

            // 3. If FEC completed a set, pull recovered data shreds into assembly
            if (fr_res == .complete) {
                const fsi = s.fecSetIndex();
                const key = fec_resolver.FecResolver.makeKey(slot_val, fsi);
                if (self.fec_resolver.active_sets.get(key)) |set| {
                    const rec_entry = self.slots.getOrPut(slot_val) catch continue;
                    if (!rec_entry.found_existing) {
                        rec_entry.value_ptr.* = self.allocator.create(SlotAssembly) catch continue;
                        rec_entry.value_ptr.*.* = SlotAssembly.init(self.allocator, slot_val);
                    }
                    const rec_assembly = rec_entry.value_ptr.*;

                    var i: u16 = 0;
                    while (i < set.data_shred_cnt) : (i += 1) {
                        if (set.data_received.isSet(i)) {
                            if (set.data_shreds[i]) |rec_shred| {
                                const global_idx = fsi + @as(u32, @intCast(i));
                                if (!rec_assembly.contains(global_idx)) {
                                    if (Shred.fromPayload(rec_shred)) |temp_shred| {
                                        const is_rec_last = temp_shred.isLastInSlot();
                                        const rec_done = rec_assembly.insert(global_idx, rec_shred, is_rec_last) catch continue;
                                        // Provenance tag (diagnostics-only, see `recovered` field doc).
                                        if (rec_assembly.contains(global_idx)) rec_assembly.markRecovered(global_idx);
                                        if (rec_done) completed = true;
                                    } else |_| continue;
                                }
                            }
                        }
                    }
                }
            }

            if (completed) {
                const assembly_completed = self.slots.get(slot_val).?;
                std.log.info("[Assembler] Slot {d} COMPLETED! Total shreds: {d}, Last index: {d}", .{ slot_val, assembly_completed.count(), assembly_completed.last_index.? });
                _ = self.highest_completed_slot.fetchMax(slot_val, .seq_cst);
                // r49-B-rev-fix-2: record the slot number so the caller can dispatch
                // replay. Without this VerifyTile path completes slots silently.
                if (result.completed_slots < result.completed_slot_list.len) {
                    result.completed_slot_list[result.completed_slots] = slot_val;
                }
                result.completed_slots += 1;
            } else {
                result.inserted += 1;
            }
        }

        return result;
    }

    pub fn getShred(self: *ShredAssembler, slot_val: u64, index: u32) !?Shred {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return null;
        const payload = assembly.getPayload(index) orelse return null;

        // Note: this makes a copy to be safe, as Shred handles its own lifetime in some paths
        const copy = try self.allocator.alloc(u8, payload.len);
        @memcpy(copy, payload);
        return try Shred.fromPayload(copy);
    }

    pub fn getHighestShredIndex(self: *ShredAssembler, slot_val: u64) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return null;
        return assembly.highest_received_index; // O(1) (see getHighestIndex); was O(32768) scan
    }

    pub fn getLastShred(self: *ShredAssembler, slot_val: u64) ?Shred {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return null;
        const idx = assembly.last_index orelse return null;
        const payload = assembly.getPayload(idx) orelse return null;

        const copy = self.allocator.alloc(u8, payload.len) catch return null;
        @memcpy(copy, payload);
        return Shred.fromPayload(copy) catch null;
    }

    /// d27n-diag (2026-05-11): per-call counter for getParentSlot — used
    /// to throttle the diagnostic log so it doesn't drown the validator
    /// log under the typical hundreds-of-calls-per-second load. Log fires
    /// for first 50 calls + every 100th + all null-return cases.
    var get_parent_call_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    pub fn getParentSlot(self: *ShredAssembler, slot_val: u64) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const call_n = get_parent_call_count.fetchAdd(1, .monotonic);
        const verbose = call_n < 50 or @mod(call_n, 100) == 0;

        const assembly = self.slots.get(slot_val) orelse {
            // null path is always informative — log unconditionally
            std.log.warn("[GET-PARENT-DIAG] slot={d} -> NULL (no assembly entry) call#{d}", .{ slot_val, call_n });
            return null;
        };
        // d27m (2026-05-11): scan for the first DATA shred specifically.
        // Coding shreds (FEC parity) do NOT carry a meaningful
        // `parent_offset` — that field is only encoded by the leader on
        // data shreds. If only coding shreds are present, parent is
        // unknown (caller falls back to default in getOrCreateBank).
        var idx: u32 = 0;
        var n_coding: u32 = 0;
        var n_payload_null: u32 = 0;
        var n_parse_fail: u32 = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            const payload = assembly.getPayload(idx) orelse {
                n_payload_null += 1;
                continue;
            };
            const s = Shred.fromPayload(payload) catch {
                n_parse_fail += 1;
                continue;
            };
            if (!s.isData()) {
                n_coding += 1;
                continue;
            }
            const offset = s.parentOffset();
            if (offset > 0 and slot_val > offset) {
                if (verbose) {
                    std.log.warn(
                        "[GET-PARENT-DIAG] slot={d} idx={d} data offset={d} -> parent={d} n_coding={d} call#{d}",
                        .{ slot_val, idx, offset, slot_val - offset, n_coding, call_n },
                    );
                }
                return slot_val - offset;
            }
            // data shred with bad offset (=0 or >= slot) — always log; rare and informative
            std.log.warn(
                "[GET-PARENT-DIAG] slot={d} idx={d} data offset={d} -> NULL (bad offset; n_coding={d}) call#{d}",
                .{ slot_val, idx, offset, n_coding, call_n },
            );
            return null;
        }
        // No data shred found across entire MAX_SHREDS scan — always log; this
        // is the suspected dominant failure mode per d27m empirical.
        std.log.warn(
            "[GET-PARENT-DIAG] slot={d} -> NULL (no data shred in scan; n_coding={d} n_payload_null={d} n_parse_fail={d}) call#{d}",
            .{ slot_val, n_coding, n_payload_null, n_parse_fail, call_n },
        );
        return null;
    }

    pub fn getCompletedSlot(self: *ShredAssembler) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.slots.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.is_complete) {
                return entry.key_ptr.*;
            }
        }
        return null;
    }

    /// fix/chain-defer-tip-guard (wedge @422050470): is `slot_val`'s block STILL
    /// fully held here (all shreds received, is_complete)? True means the child's
    /// bytes can be re-derived via getAssembledDataWithBoundaries even though its
    /// CHAIN-DEFER map entry (a separate copy) was GC-evicted — the self-heal
    /// witness for the CHAIN-WAKE fallback. The completed SlotAssembly survives
    /// defer-map GC; only clearRootedSlots (below the root) frees it.
    pub fn isSlotComplete(self: *ShredAssembler, slot_val: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.slots.get(slot_val)) |assembly| return assembly.is_complete;
        return false;
    }

    pub fn clearCompletedSlot(self: *ShredAssembler, slot_val: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.slots.fetchRemove(slot_val)) |entry| {
            if (self.frame_manager) |fm| {
                entry.value.deinitWithFrameManager(fm);
            } else {
                entry.value.deinit();
            }
        }
        self.fec_resolver.removeSlot(slot_val);
    }

    pub fn removeSlot(self: *ShredAssembler, slot_val: u64) void {
        self.clearCompletedSlot(slot_val);
    }

    /// Task #71 L3 leak fix (2026-06-11): free EVERY assembly for slots
    /// strictly below `min_keep_slot` (caller passes the rooted/prune cutoff).
    /// A rooted slot is final — replay can never need its shreds again.
    /// Without this, completed assemblies were NEVER freed anywhere: the
    /// stale sweeper skips `is_complete` entries by design (replay retry may
    /// re-read an above-root assembly — the 2026-05-26 wedge lesson), and the
    /// two designated cleanup hooks (clearCompletedSlot / TVU clearPendingSlot)
    /// had ZERO callers. Net effect: ~2.5 MB leaked per completed slot
    /// (1.3 MB inline SlotAssembly struct + copied shred payloads) ≈ the
    /// entire ~25 GB/h at-tip RSS slope. jeprof proof (2026-06-11, dumps
    /// 300→1057, 12 min at tip): 97.3% of live-byte growth under
    /// VerifyTile.verifyWorkerLoop → insertBatch → Allocator.create.
    /// Everything at or above `min_keep_slot` is left untouched (replay
    /// retries + repair still work). Returns the number of slots freed.
    pub fn clearRootedSlots(self: *ShredAssembler, min_keep_slot: u64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var doomed: std.ArrayListUnmanaged(u64) = .{};
        defer doomed.deinit(self.allocator);
        var it = self.slots.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < min_keep_slot)
                doomed.append(self.allocator, entry.key_ptr.*) catch break;
        }
        for (doomed.items) |slot_key| {
            if (self.slots.fetchRemove(slot_key)) |removed| {
                if (self.frame_manager) |fm| {
                    removed.value.deinitWithFrameManager(fm);
                } else {
                    removed.value.deinit();
                }
            }
            self.fec_resolver.removeSlot(slot_key);
        }
        return doomed.items.len;
    }

    pub fn assembleSlot(self: *ShredAssembler, slot_val: u64) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return null;
        if (!assembly.is_complete) return null;

        const last = assembly.last_index.?;

        var gap_count: u32 = 0;
        {
            var gi: u32 = 0;
            while (gi <= last) : (gi += 1) {
                const sd = assembly.getPayload(gi) orelse {
                    gap_count += 1;
                    continue;
                };
                if (sd.len < 88) {
                    gap_count += 1;
                    continue;
                }
            }
        }
        if (gap_count > 0) {
            std.log.debug("[ASSEMBLY-GAP] slot={d} gaps={d} out of {d} — REFUSING to assemble\n", .{
                slot_val, gap_count, last + 1,
            });
            return null;
        }

        // ══════════════════════════════════════════════════════════════════
        // SHRED ASSEMBLY:
        // data_size (bytes 86-87) includes headers (88 bytes).
        // Payload bytes = data_size - 88, starting at byte 88.
        // This is correct for ALL variants (unchained, chained, resigned).
        // ══════════════════════════════════════════════════════════════════

        // Pass 1: Count total bytes
        var total_size: usize = 0;
        var chained_count: u32 = 0;
        var unchained_count: u32 = 0;
        var i: u32 = 0;
        while (i <= last) : (i += 1) {
            const shred_data = assembly.getPayload(i) orelse continue;
            if (shred_data.len < 88) continue;

            const variant = shred_data[64];
            const high_nibble = variant & 0xF0;

            // Data shreds: Merkle (0x80, 0x90, 0xA0 excl 0xA5, 0xB0) and legacy (0xA5)
            const is_data = (high_nibble == 0x80 or high_nibble == 0x90 or
                (high_nibble == 0xA0 and variant != 0xA5) or high_nibble == 0xB0 or
                variant == 0xA5);
            if (!is_data) continue;

            if (high_nibble == 0x90 or high_nibble == 0xB0) {
                chained_count += 1;
            } else {
                unchained_count += 1;
            }

            const raw_size = std.mem.readInt(u16, shred_data[86..88], .little);
            if (raw_size <= 88) continue;
            const clamped: u16 = @min(raw_size, @as(u16, @intCast(shred_data.len)));
            if (clamped <= 88) continue;
            total_size += clamped - 88;
        }

        // DIAGNOSTIC: Analyze batch_complete flags and zero-payload shreds
        {
            var first_zero_idx: ?u32 = null;
            var diag_zero_payload_count: u32 = 0;
            var nonzero_payload_count: u32 = 0;
            var batch_complete_indices: [16]u32 = [_]u32{0} ** 16;
            var batch_complete_count: u32 = 0;
            var diag_i: u32 = 0;

            while (diag_i <= last) : (diag_i += 1) {
                const sd = assembly.getPayload(diag_i) orelse continue;
                if (sd.len < 88) continue;

                const data_flags = sd[85]; // offset 0x55 = byte 85
                const batch_complete = (data_flags & 0x40) != 0;
                const block_complete = (data_flags & 0x80) != 0;

                if (batch_complete and batch_complete_count < 16) {
                    batch_complete_indices[batch_complete_count] = diag_i;
                    batch_complete_count += 1;
                }

                // Check if payload (bytes 88..data_size) is all zeros
                const raw_size = std.mem.readInt(u16, sd[86..88], .little);
                if (raw_size > 88) {
                    const end = @min(raw_size, @as(u16, @intCast(sd.len)));
                    if (end > 88) {
                        var all_zero = true;
                        // Check first 32 bytes of payload for speed
                        const check_end = @min(end, 120);
                        for (sd[88..check_end]) |b| {
                            if (b != 0) {
                                all_zero = false;
                                break;
                            }
                        }
                        if (all_zero) {
                            diag_zero_payload_count += 1;
                            if (first_zero_idx == null) first_zero_idx = diag_i;
                        } else {
                            nonzero_payload_count += 1;
                        }
                    }
                }

                // Log details for the boundary region
                if (first_zero_idx != null and diag_i == first_zero_idx.?) {
                    std.log.debug("[ZERO-SHRED] slot={d} FIRST_ZERO idx={d} data_size={d} flags=0x{x:0>2} batch_complete={} block_complete={}\n", .{
                        slot_val, diag_i, raw_size, data_flags, batch_complete, block_complete,
                    });
                    // Also log the shred just BEFORE the first zero
                    if (diag_i > 0) {
                        if (assembly.getPayload(diag_i - 1)) |prev| {
                            if (prev.len >= 88) {
                                const prev_flags = prev[85];
                                const prev_ds = std.mem.readInt(u16, prev[86..88], .little);
                                std.log.debug("[ZERO-SHRED] slot={d} LAST_GOOD idx={d} data_size={d} flags=0x{x:0>2} batch_complete={} block_complete={}\n", .{
                                    slot_val,                 diag_i - 1,               prev_ds, prev_flags,
                                    (prev_flags & 0x40) != 0, (prev_flags & 0x80) != 0,
                                });
                            }
                        }
                    }
                }
            }

            // Summary
            if (diag_zero_payload_count > 0) {
                std.log.debug("[ZERO-SHRED] slot={d} nonzero={d} zero={d} first_zero_at={d} last={d} batch_completes={d}", .{
                    slot_val,                   nonzero_payload_count, diag_zero_payload_count,
                    first_zero_idx orelse 9999, last,                  batch_complete_count,
                });
                // Print batch_complete indices
                if (batch_complete_count > 0) {
                    std.log.debug(" bc_at=[", .{});
                    for (0..batch_complete_count) |bi| {
                        if (bi > 0) std.log.debug(",", .{});
                        std.log.debug("{d}", .{batch_complete_indices[bi]});
                    }
                    std.log.debug("]", .{});
                }
                std.log.debug("\n", .{});
            }
        }

        std.log.debug("[Assembler] Assembling slot {d} with {d} bytes from {d} shreds", .{ slot_val, total_size, last + 1 });

        const result = try self.allocator.alloc(u8, total_size);
        var offset: usize = 0;
        i = 0;
        while (i <= last) : (i += 1) {
            const shred_data = assembly.getPayload(i) orelse continue;
            if (shred_data.len < 88) continue;

            const variant = shred_data[64];
            const high_nibble = variant & 0xF0;
            const is_data = (high_nibble == 0x80 or high_nibble == 0x90 or
                (high_nibble == 0xA0 and variant != 0xA5) or high_nibble == 0xB0 or
                variant == 0xA5);
            if (!is_data) continue;

            const raw_size = std.mem.readInt(u16, shred_data[86..88], .little);
            if (raw_size <= 88) continue;
            const clamped: u16 = @min(raw_size, @as(u16, @intCast(shred_data.len)));
            if (clamped <= 88) continue;
            const data_len = clamped - 88;

            if (offset + data_len > total_size) {
                std.log.debug("[Assembler] Buffer overflow in slot {d}! offset={d} len={d} total={d}\n", .{ slot_val, offset, data_len, total_size });
                break;
            }
            @memcpy(result[offset .. offset + data_len], shred_data[88 .. 88 + data_len]);
            offset += data_len;
        }

        return result;
    }

    pub fn getHighestCompletedSlot(self: *ShredAssembler) ?u64 {
        const val = self.highest_completed_slot.load(.seq_cst);
        return if (val == 0) null else val;
    }

    pub fn getInProgressSlots(self: *ShredAssembler) ![]u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var slots = std.ArrayListUnmanaged(u64){};
        var it = self.slots.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.*.is_complete) {
                try slots.append(self.allocator, entry.key_ptr.*);
            }
        }
        return slots.toOwnedSlice(self.allocator);
    }

    pub fn getInProgressSlotCount(self: *ShredAssembler) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var it = self.slots.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.*.is_complete) {
                count += 1;
            }
        }
        return count;
    }

    /// Diagnostic (2026-06-13): single-pass min/max slot + count of incomplete
    /// slots ABOVE a reference (tip proxy = max_slot_seen). Phantom far-future
    /// minting shows up as max_slot >> ref and count_above > 0. Used to decide
    /// whether the AF_XDP in-progress-slot explosion is legit catch-up backlog
    /// or misparsed/phantom slot entries.
    pub const InProgStats = struct {
        count: usize = 0,
        min_slot: u64 = 0,
        max_slot: u64 = 0,
        count_above: usize = 0, // incomplete slots with key > ref
    };
    pub fn inProgressStats(self: *ShredAssembler, ref: u64) InProgStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var s = InProgStats{};
        var it = self.slots.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.is_complete) continue;
            const k = entry.key_ptr.*;
            s.count += 1;
            if (s.min_slot == 0 or k < s.min_slot) s.min_slot = k;
            if (k > s.max_slot) s.max_slot = k;
            if (k > ref) s.count_above += 1;
        }
        return s;
    }

    pub const SlotInfo = struct {
        knows_last_shred: bool,
        unique_count: usize,
        last_shred_index: u32,
    };

    pub fn getSlotInfo(self: *ShredAssembler, slot_val: u64) !SlotInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return SlotInfo{
            .knows_last_shred = false,
            .unique_count = 0,
            .last_shred_index = 0,
        };

        return SlotInfo{
            .knows_last_shred = assembly.last_index != null,
            .unique_count = assembly.count(),
            .last_shred_index = assembly.last_index orelse 0,
        };
    }

    pub fn getMissingIndices(self: *ShredAssembler, slot_val: u64) ![]u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return &.{};
        if (assembly.is_complete) return &.{};

        var missing = std.ArrayListUnmanaged(u32){};
        if (assembly.last_index) |last| {
            var i: u32 = 0;
            while (i <= last) : (i += 1) {
                if (!assembly.contains(i)) {
                    try missing.append(self.allocator, i);
                }
            }
        }
        return missing.toOwnedSlice(self.allocator);
    }

    /// Get the highest shred index we've seen for a slot
    pub fn getHighestIndex(self: *ShredAssembler, slot_val: u64) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return 0;
        // O(1): highest_received_index is maintained on every received.set (:253-317),
        // so it == max{idx : received.isSet(idx)}. Was an O(32768) bitset scan per call
        // (hot: fired per-repair-cycle from tvu requestHighestWindowIndex).
        return assembly.highest_received_index;
    }

    /// Get assembled data for a completed slot — concatenates all data shred payloads in order.
    /// Caller owns the returned slice.
    pub fn getAssembledData(self: *ShredAssembler, slot_val: u64) ![]u8 {
        const ar = try self.getAssembledDataWithBoundaries(slot_val);
        // Free unused boundaries — legacy callers don't consume them
        if (ar.boundaries.len > 0) self.allocator.free(ar.boundaries);
        return ar.data;
    }

    pub const AssembledResult = struct {
        data: []u8,
        /// Byte offsets in `data` where each BlockComponent ENDS (and the next
        /// one begins). Derived from per-shred `batch_complete` flag (data
        /// shred header byte 85 & 0x40 — agave-4.0/ledger/src/shred/*).
        /// Maps 1:1 to gov blockstore's `completed_data_indexes` (a per-shred
        /// bitmap of "this shred ended a block_component"). Used by the replay
        /// parser to jump straight from the end of one component (which may
        /// have intra-shred zero padding) to the start of the next, without
        /// the byte-by-byte scan-forward heuristic.
        ///
        /// Empty when the slot has only one component (then `data` IS the
        /// component and the parser walks it normally).
        boundaries: []usize,
    };

    /// @prov:shred.assembled-boundaries — d27hh: returns assembled slot data
    /// plus per-BlockComponent boundary offsets, carving the slot into
    /// independently-deserialized components based on shred-level
    /// `batch_complete` flags. Each boundary[i] is the byte
    /// offset in `data` immediately AFTER the i-th component's last byte.
    pub fn getAssembledDataWithBoundaries(self: *ShredAssembler, slot_val: u64) !AssembledResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return error.SlotNotFound;
        if (!assembly.is_complete) return error.SlotNotComplete;

        // Calculate total size from data shred payloads.
        // Key: bytes 86-87 contain data_size (LE u16) which INCLUDES the 88-byte header.
        // Actual payload = data_size - 88, starting at byte 88.
        // This is correct for ALL shred variants (legacy, Merkle unchained/chained/resigned).
        // Using payload.len instead would include Merkle proof bytes as garbage entry data.
        const HDR_SZ: usize = shred_parse.SHRED_HEADER_SIZE;
        var total_size: usize = 0;
        var idx: u32 = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            if (!assembly.received.isSet(idx)) break;
            if (assembly.getPayload(idx)) |payload| {
                if (payload.len >= HDR_SZ) {
                    // Skip coding shreds — only data shreds have valid entry data
                    if (!fec_resolver.parseVariantByte(payload[64]).is_data) continue;
                    const raw_size = std.mem.readInt(u16, payload[86..88], .little);
                    if (raw_size > HDR_SZ) {
                        const clamped = @min(@as(usize, raw_size), payload.len);
                        if (clamped > HDR_SZ) {
                            total_size += clamped - HDR_SZ;
                        }
                    }
                }
            } else break;
        }

        if (total_size == 0) return error.EmptySlot;

        // Allocate and concatenate (header-stripped, data_size-bounded payloads)
        const result = try self.allocator.alloc(u8, total_size);
        var boundaries = std.ArrayListUnmanaged(usize){};
        errdefer {
            boundaries.deinit(self.allocator);
            self.allocator.free(result);
        }
        var offset: usize = 0;
        idx = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            if (!assembly.received.isSet(idx)) break;
            if (assembly.getPayload(idx)) |payload| {
                if (payload.len >= HDR_SZ) {
                    // Skip coding shreds (defense-in-depth)
                    if (!fec_resolver.parseVariantByte(payload[64]).is_data) continue;
                    const raw_size = std.mem.readInt(u16, payload[86..88], .little);
                    if (raw_size > HDR_SZ) {
                        const clamped = @min(@as(usize, raw_size), payload.len);
                        if (clamped > HDR_SZ) {
                            const data_len = clamped - HDR_SZ;
                            @memcpy(result[offset..][0..data_len], payload[HDR_SZ..][0..data_len]);
                            offset += data_len;
                            // d27hh: detect block_component boundary via
                            // batch_complete flag (data shred flags byte 85,
                            // mask 0x40). This shred is the final shred of
                            // its FEC set / block_component — the next shred
                            // starts a new component.
                            const data_flags = payload[85];
                            if ((data_flags & 0x40) != 0) {
                                // incident-422359406 (2026-07-16) postmortem: unlike the
                                // FEC-BOUNDARY-GUARD for 0x80 LAST_IN_SLOT (init handleLastAndComplete,
                                // ~line 340), a 0x40 DATA_COMPLETE boundary on a FEC-RECOVERED shred
                                // is deliberately NOT withheld here. 0x80 has a hard positional
                                // invariant (always at fec_set_index+31) so withholding an off-boundary
                                // one can only kill a spurious flag; 0x40 has NO such invariant —
                                // Agave-produced blocks legitimately end an entry batch anywhere, so a
                                // blind withhold-unless-corroborated heuristic risks suppressing an
                                // HONEST boundary and truncating a good block (worse than the incident
                                // it would guard against). Instead the corroboration already happens
                                // one layer down, cryptographically: fec_resolver.zig recoverWithSigMethod
                                // (@prov:fec.chained-merkle-recovery, ~line 1558-1576) rebuilds the FULL
                                // 64-leaf FEC-set merkle tree from the RS-recovered shreds and REJECTS
                                // the whole set (installs nothing) unless the rebuilt root equals the
                                // leader-signed root — the RS-recovered region starts at shred offset 64
                                // and covers the 24-byte data header (hence flags byte 85) same as any
                                // other leaf byte, so a recovered shred that entered assembly already had
                                // its 0x40 bit cryptographically confirmed against what the leader
                                // signed. This is byte-for-byte the same gate Agave runs on its own
                                // recovery path (ledger/src/shred/merkle.rs:837
                                // `if tree.root() != &merkle_root { return Err(InvalidMerkleRoot) }`) —
                                // see katPositive / "#61 chained FEC recovery KAT" in fec_resolver.zig for
                                // the byte-exact (incl. offset 85) and reject-on-corruption proofs.
                                // Empirically confirmed for THIS incident's exact slot: offline-replaying
                                // 422359406's canonical shreds through this UNMODIFIED code path froze to
                                // the exact canonical bank_hash 86AprRYZ4bLLDmr86WNtxZvp5r77PTdAkq9QLbz1GEwk
                                // (gate-scratch/gate-406-replay-prefix.log) — no truncation reproduces from
                                // correct bytes, consistent with the corruption (if any) having been in
                                // OUR node's own live wire reception that day, not in this boundary logic.
                                // What DOES change here: provenance is now logged (closing the "not
                                // logged" gap the postmortem called out) so a future recurrence is
                                // diagnosable without a multi-hour forensic reconstruction.
                                if (assembly.recovered.isSet(idx)) {
                                    std.log.info(
                                        "[FEC-DATACOMPLETE-OBSERVE] slot {d}: DATA_COMPLETE (0x40) boundary at FEC-recovered index {d}, offset {d} — trusted (root-gate verified at recovery time, see fec_resolver.zig #61); boundary NOT withheld",
                                        .{ assembly.slot, idx, offset },
                                    );
                                }
                                boundaries.append(self.allocator, offset) catch {};
                            }
                        }
                    }
                }
            } else break;
        }

        // AF_XDP CATCHUP DEADLOCK FIX (2026-05-26): convert all held UMEM
        // frames into heap copies, then release the frames back to the Fill
        // Ring. Without this, every assembled-but-not-replayed slot (typical
        // during catchup CHAIN-DEFER) hoards ~600 frames; ~50 such slots
        // exhaust the 32K UMEM pool → fill ring drains → kernel drops every
        // incoming shred → can't bridge ancestor gap.
        //
        // Heap-copy (not just release) keeps downstream consumers transparent:
        //   - checkLastFecSet32 (replay_stage.zig:2212) — derives SIMD-0340
        //     block_id from last 32 data shreds' merkle root
        //   - firstShredChainedMerkleRoot (replay_stage.zig:2219) — child's
        //     chained_merkle_root for parent block_id comparison
        // Both call `getPayload(idx)` which falls back to `copied[idx]`.
        //
        // Safety: we hold `self.mutex` here, so no concurrent inserter race.
        // On allocator failure, returns OutOfMemory and leaves SlotAssembly
        // unchanged (no partial release). The data slot result is still
        // valid — caller can proceed; we simply don't free the frames this
        // cycle (next slot's call will retry).
        if (self.frame_manager) |fm| {
            const released = assembly.convertFramesToCopiesAndRelease(fm) catch |alloc_err| blk: {
                std.log.warn(
                    "[ASSEMBLER-FRAME-RELEASE] slot={d} convert failed: {any} — keeping frames held (next slot retries)",
                    .{ slot_val, alloc_err },
                );
                break :blk 0;
            };
            if (released > 0) {
                std.log.debug(
                    "[ASSEMBLER-FRAME-RELEASE] slot={d} released={d} (data copied to heap, frames returned to UMEM pool)",
                    .{ slot_val, released },
                );
            }
        }

        return .{ .data = result, .boundaries = try boundaries.toOwnedSlice(self.allocator) };
    }

    /// One persisted data shred: its index + a COPY of the raw wire bytes.
    pub const RawDataShred = struct { index: u32, wire: []u8 };

    /// Owned (index, raw wire bytes) for the slot's present DATA shreds, ascending
    /// index. The caller frees each `.wire` AND the returned slice (same allocator).
    /// Empty slice if the slot is absent. ADDITIVE / read-only — does not touch any
    /// existing function. Used by the VexLedger persist tap to store shreds verbatim;
    /// it mirrors getAssembledDataWithBoundaries' iteration (lock + received-set
    /// contiguity + data-only variant filter) so it sees the same shred set.
    pub fn getRawDataShredsForSlot(self: *ShredAssembler, allocator: std.mem.Allocator, slot_val: u64) ![]RawDataShred {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return &.{};

        var out = std.ArrayListUnmanaged(RawDataShred){};
        errdefer {
            for (out.items) |r| allocator.free(r.wire);
            out.deinit(allocator);
        }

        var idx: u32 = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            if (!assembly.received.isSet(idx)) break;
            if (assembly.getPayload(idx)) |payload| {
                if (payload.len >= shred_parse.SHRED_HEADER_SIZE and fec_resolver.parseVariantByte(payload[64]).is_data) {
                    const wire = try allocator.dupe(u8, payload);
                    try out.append(allocator, .{ .index = idx, .wire = wire });
                }
            } else break;
        }
        return out.toOwnedSlice(allocator);
    }

    /// incident-422359406 follow-up (2026-07-16): on a REPLAY FAILURE (the
    /// BadBlockTickValidity path that dumps the assembled entry buffer to
    /// /tmp/vex_slot_<slot>_fail.bin — replay_stage.zig replayEntries' catch
    /// branch, ~line 7044), ALSO dump the raw per-shred records with
    /// FEC-recovery provenance and the component boundaries the assembler
    /// derived. Closes the exact forensic gap this incident hit — the RCA's
    /// own postmortem noted "our corrupted raw shred set was never
    /// preserved, only the post-assembly buffer" (CANONICAL-COMPARISON.md),
    /// which is why the RCA could only hypothesize a mechanism rather than
    /// prove one. Failure-path-only (called from replayEntries' error
    /// branch, never the hot insert path — zero steady-state cost);
    /// best-effort (swallows I/O errors — a failed diagnostic dump must
    /// never mask or worsen the original replay failure it's reacting to).
    ///
    /// File format (/tmp/vex_slot_<slot>_shreds.bin), all integers
    /// little-endian:
    ///   magic:          4 bytes "VSD1"
    ///   version:        u8 = 1
    ///   slot:           u64
    ///   num_boundaries: u32
    ///   boundaries:     num_boundaries * u64  (byte offsets into the
    ///                   assembled buffer — same values getAssembledData-
    ///                   WithBoundaries returned / component_boundaries_-
    ///                   override held at replay time)
    ///   num_records:    u32
    ///   records: num_records * {
    ///     index:      u32  (data-shred index within the slot)
    ///     recovered:  u8   (1 = entered assembly via the FEC pull-in path,
    ///                       see SlotAssembly.recovered; 0 = direct network
    ///                       insert)
    ///     len:        u16  (raw wire payload length, as received/
    ///                       reconstructed, capped at u16 max)
    ///     payload:    len bytes (verbatim — header, flags byte 85, merkle
    ///                       proof, everything getPayload() returns)
    ///   }
    /// Same received-set contiguous-prefix + is_data-variant walk as
    /// getAssembledDataWithBoundaries / getRawDataShredsForSlot, so records
    /// line up 1:1 with what the failed assembly actually consumed.
    pub fn dumpSlotShredsWithProvenance(self: *ShredAssembler, slot_val: u64, boundaries: []const usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return;

        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/tmp/vex_slot_{d}_shreds.bin", .{slot_val}) catch return;
        const file = std.fs.cwd().createFile(path, .{}) catch |e| {
            std.log.err("[REPLAY] Failed to create shred-provenance dump file: {any}", .{e});
            return;
        };
        defer file.close();

        file.writeAll("VSD1") catch return;
        file.writeAll(&[_]u8{1}) catch return; // version

        var u64buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &u64buf, slot_val, .little);
        file.writeAll(&u64buf) catch return;

        var u32buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &u32buf, @intCast(boundaries.len), .little);
        file.writeAll(&u32buf) catch return;
        for (boundaries) |b| {
            std.mem.writeInt(u64, &u64buf, @intCast(b), .little);
            file.writeAll(&u64buf) catch return;
        }

        // Pass 1: count present data-shred records (same contiguous-prefix +
        // is_data walk as getAssembledDataWithBoundaries) so the header can
        // carry num_records before the records themselves.
        var count: u32 = 0;
        var idx: u32 = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            if (!assembly.received.isSet(idx)) break;
            if (assembly.getPayload(idx)) |payload| {
                if (payload.len >= shred_parse.SHRED_HEADER_SIZE and fec_resolver.parseVariantByte(payload[64]).is_data) count += 1;
            } else break;
        }
        std.mem.writeInt(u32, &u32buf, count, .little);
        file.writeAll(&u32buf) catch return;

        // Pass 2: write records.
        idx = 0;
        while (idx < SlotAssembly.MAX_SHREDS_PER_SLOT) : (idx += 1) {
            if (!assembly.received.isSet(idx)) break;
            const payload = assembly.getPayload(idx) orelse break;
            if (payload.len < shred_parse.SHRED_HEADER_SIZE or !fec_resolver.parseVariantByte(payload[64]).is_data) continue;

            std.mem.writeInt(u32, &u32buf, idx, .little);
            file.writeAll(&u32buf) catch return;
            file.writeAll(&[_]u8{if (assembly.recovered.isSet(idx)) @as(u8, 1) else 0}) catch return;
            const len: u16 = @intCast(@min(payload.len, @as(usize, std.math.maxInt(u16))));
            var u16buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &u16buf, len, .little);
            file.writeAll(&u16buf) catch return;
            file.writeAll(payload[0..len]) catch return;
        }

        // .warn not .err: this fires unconditionally whenever the caller (a
        // real replay failure) invokes the dump, but the dump ITSELF
        // succeeding is not an error condition — keep it out of the same
        // severity bucket as an actual failure so log-level-based test
        // harnesses (and any future err-triggered alerting) don't conflate
        // "we captured forensics" with "something is still wrong."
        std.log.warn("[REPLAY] Dumped {d} shred records (provenance+boundaries) for slot {d} to {s}", .{ count, slot_val, path });
    }

    /// Check if we have a specific shred for a slot (lock-free from TVU thread)
    pub fn hasShred(self: *ShredAssembler, slot_val: u64, shred_idx: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const assembly = self.slots.get(slot_val) orelse return false;
        if (shred_idx >= SlotAssembly.MAX_SHREDS_PER_SLOT) return false;
        return assembly.received.isSet(shred_idx);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "FIX #56: chainedMerkleRoot returns spurious value when shred buffer is over-allocated" {
    // Reproduces the byte-pattern of slot 411265948's first shred during the
    // 2026-05-27 14:02 UTC wedge: a recovered data shred allocated at 1228B
    // (coding-shred size) instead of 1203B (data-shred size). The 25 trailing
    // bytes are zero (memset), AND bytes [1083..1203) are also zero because
    // Reed-Solomon recovery never reconstructs the merkle proof region.
    // `chainedMerkleRoot()` reads at offset proof_start-32 .. proof_start, with
    // proof_start computed from payload.len:
    //   - canonical 1203B: proof_start=1083 → reads [1051..1083] = correct
    //   - bug-path  1228B: proof_start=1108 → reads [1076..1108] = spurious
    //
    // See memory: project-fix56-fec-recovery-shred-size-bug-2026-05-27

    const allocator = std.testing.allocator;

    // Build a minimal chained data shred at the CORRECT 1203B size.
    const canonical = try allocator.alloc(u8, 1203);
    defer allocator.free(canonical);
    @memset(canonical, 0);

    // Variant byte at offset 64: chained merkle data, proof_size=6.
    // 0x90 = chained data (not resigned), low nibble = proof_size.
    canonical[64] = 0x96;

    // Place a known-good 32-byte chained_merkle_root at the canonical position.
    // For chained-not-resigned, proof_size=6, payload=1203:
    //   suffix_after_proof = 0
    //   proof_end          = 1203
    //   proof_start        = 1203 - 6*20 = 1083
    //   chained_root span  = [1083-32 .. 1083) = [1051 .. 1083)
    const known_root = [_]u8{
        0xae, 0xd8, 0x77, 0xaf, 0xfc, 0xa7, 0xd6, 0x5a,
        0xe8, 0xbb, 0x6b, 0x74, 0x0e, 0x87, 0x6f, 0x84,
        0x2c, 0x52, 0xd8, 0xfa, 0xe7, 0x44, 0x7a, 0xa7,
        0x3a, 0x99, 0xe9, 0xad, 0x78, 0xbd, 0xf6, 0xf8,
    };
    @memcpy(canonical[1051..1083], &known_root);

    const s_good = try parseShred(canonical);
    const root_good = s_good.chainedMerkleRoot() orelse return error.CanonicalNullRoot;
    try std.testing.expectEqualSlices(u8, &known_root, &root_good);

    // Now reproduce the BUG: alloc 1228 and copy canonical 1203B into the first
    // 1203 bytes. Bytes [1203..1228) remain zero from memset; bytes [1083..1203)
    // (proof region in canonical) are also zero — matches RS-recovered state.
    const oversize = try allocator.alloc(u8, 1228);
    defer allocator.free(oversize);
    @memset(oversize, 0);
    @memcpy(oversize[0..1203], canonical);

    const s_bug = try parseShred(oversize);
    const root_bug = s_bug.chainedMerkleRoot() orelse return error.BugNullRoot;

    // First 7 bytes of root_bug must equal known_root[25..32] (the tail of the
    // correct chained_root field, which falls inside the wrong read window).
    // The remaining 25 bytes must be zero (proof region of canonical + trailing
    // pad of oversize, both unwritten).
    var expected_bug: [32]u8 = undefined;
    @memset(&expected_bug, 0);
    @memcpy(expected_bug[0..7], known_root[25..32]);
    try std.testing.expectEqualSlices(u8, &expected_bug, &root_bug);

    // And the bug-path MUST differ from the canonical (regression guard).
    try std.testing.expect(!std.mem.eql(u8, &known_root, &root_bug));
}

test "task #71 L3: clearRootedSlots frees rooted assemblies (incl. COMPLETED) and keeps everything at/above root" {
    // The at-tip ~25 GB/h leak: completed SlotAssembly entries (~1.3 MB inline
    // struct + copied payloads) were NEVER freed — the stale sweeper skips
    // is_complete entries by design and clearCompletedSlot had zero callers.
    // This KAT FAILS on pre-fix code two ways: (a) clearRootedSlots didn't
    // exist; (b) leaving the loop below without it makes std.testing.allocator
    // report the leaked assemblies + payloads as a test failure.
    const allocator = std.testing.allocator;
    const assembler = try ShredAssembler.init(allocator);
    defer assembler.deinit();

    // Build 4 assemblies straight into the map the way insertBatch does:
    // slots 100 (complete), 101 (incomplete), 200 (complete), 201 (incomplete).
    const slots_in = [_]struct { slot: u64, complete: bool }{
        .{ .slot = 100, .complete = true },
        .{ .slot = 101, .complete = false },
        .{ .slot = 200, .complete = true },
        .{ .slot = 201, .complete = false },
    };
    for (slots_in) |s| {
        const entry = try assembler.slots.getOrPut(s.slot);
        entry.value_ptr.* = try allocator.create(ShredAssembler.SlotAssembly);
        entry.value_ptr.*.* = ShredAssembler.SlotAssembly.init(allocator, s.slot);
        // Give each assembly an owned payload so a missed free is VISIBLE to
        // the testing allocator (mirrors the copied-payload path).
        const payload = try allocator.alloc(u8, 1200);
        @memset(payload, 0xAB);
        entry.value_ptr.*.copied[0] = payload;
        entry.value_ptr.*.received_count = 1;
        entry.value_ptr.*.is_complete = s.complete;
    }
    try std.testing.expectEqual(@as(usize, 4), assembler.slots.count());

    // Root advanced to 200: slots 100+101 are final history; 200/201 must stay.
    const freed = assembler.clearRootedSlots(200);
    try std.testing.expectEqual(@as(usize, 2), freed);
    try std.testing.expectEqual(@as(usize, 2), assembler.slots.count());
    try std.testing.expect(assembler.slots.get(100) == null); // completed BELOW root: freed (the leak class)
    try std.testing.expect(assembler.slots.get(101) == null); // incomplete below root: freed
    try std.testing.expect(assembler.slots.get(200) != null); // at root: kept
    try std.testing.expect(assembler.slots.get(201) != null); // above root: kept (replay retry)

    // Idempotent + no-op below current floor.
    try std.testing.expectEqual(@as(usize, 0), assembler.clearRootedSlots(200));
    // Advancing past everything frees the rest (proves no entry is sticky).
    try std.testing.expectEqual(@as(usize, 2), assembler.clearRootedSlots(10_000));
    try std.testing.expectEqual(@as(usize, 0), assembler.slots.count());
}

test "FEC-boundary guard (FD:544): off-boundary LAST_IN_SLOT withheld; on-boundary completes" {
    // Reproduces slot 413204194's TooFewTicks dead-slot: a LAST_IN_SLOT (0xC0)
    // flag arrived at data-shred index 258, but (258+1)%32 = 3 ≠ 0, so 258 is
    // NOT an FEC-set boundary. In the canonical merkle shred format every FEC
    // set (incl. the final one) holds exactly 32 data shreds, so the true last
    // is ALWAYS at fec_set_index+31 — here index 287 (set 256 spans 256..287).
    // Vexor historically sealed last_index=258, parsed a 61-tick block, and the
    // tick-gate markSlotDead'd it → fork-choice collapse → delinquent.
    // FD fd_fec_resolver.c:544 rejects this UNCONDITIONALLY. The guard withholds
    // the last-flag so the slot stays incomplete until the true tail arrives.
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const dummy = [_]u8{0}; // guard operates on index/is_last only, not payload

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, 413204194);
    defer sa.deinit();

    // Feed the dense prefix 0..257 (no last flag yet).
    var i: u32 = 0;
    while (i < 258) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }

    // Adversarial OFF-BOUNDARY LAST at index 258 — must be WITHHELD.
    const completed_bad = try sa.insert(258, &dummy, true);
    try std.testing.expect(!completed_bad); // did NOT complete
    try std.testing.expect(!sa.is_complete);
    try std.testing.expectEqual(@as(?u32, null), sa.last_index); // last-flag withheld
    try std.testing.expectEqual(@as(u32, 259), sa.received_count); // but the shred IS kept
    try std.testing.expect(sa.contains(258));

    // The true tail 259..286 (no last flag).
    i = 259;
    while (i < 287) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }
    try std.testing.expect(!sa.is_complete); // still incomplete — no honored last

    // Real ON-BOUNDARY LAST at index 287: (287+1)%32 = 0 → honored → completes.
    const completed_good = try sa.insert(287, &dummy, true);
    try std.testing.expect(completed_good);
    try std.testing.expect(sa.is_complete);
    try std.testing.expectEqual(@as(?u32, 287), sa.last_index);
    try std.testing.expectEqual(@as(u32, 288), sa.received_count);
}

test "contiguity gate (incident 421935259): holes below last_index masked by shreds above it must NOT complete" {
    // Reproduces the 421935259 false-completion shape: the node held the block
    // HEAD plus scattered tail shreds, a last-flag sealed last_index, and
    // received_count (which also counts shreds with index > last_index) reached
    // last+1 while a HOLE remained below last — the count-based predicate
    // declared the slot complete and a 30/64-tick truncated assembly was
    // frozen+voted. The contiguity check (Agave is_full) must keep the slot
    // incomplete until repair fills the hole, then complete it.
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const dummy = [_]u8{0};

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, 421935259);
    defer sa.deinit();

    // Head 0..249 (250 shreds).
    var i: u32 = 0;
    while (i < 250) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }
    // Scattered tail 320..350 (hole at 250..319).
    i = 320;
    while (i < 351) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }
    // ON-BOUNDARY last at 351 ((351+1)%32==0, >= highest) — honored.
    try std.testing.expect(!(try sa.insert(351, &dummy, true)));
    try std.testing.expectEqual(@as(?u32, 351), sa.last_index);
    try std.testing.expectEqual(@as(u32, 282), sa.received_count); // 250+31+1 < 352

    // Shreds ABOVE last_index (nothing rejects them; they inflate the count —
    // the exact masking mechanism). 352..421 = 70 shreds -> count hits 352
    // (= last+1) at i=421. The OLD count-based predicate completed HERE.
    i = 352;
    while (i < 422) : (i += 1) {
        const completed = try sa.insert(i, &dummy, false);
        try std.testing.expect(!completed); // contiguity gate: hole 250..319 open
    }
    try std.testing.expectEqual(@as(u32, 352), sa.received_count);
    try std.testing.expect(!sa.is_complete); // OLD code: true (the incident); NEW: false

    // Repair fills the hole 250..319 — completion fires exactly when 0..=351
    // becomes contiguous (the final hole-filling insert).
    i = 250;
    while (i < 319) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }
    const completed = try sa.insert(319, &dummy, false); // last hole filled
    try std.testing.expect(completed);
    try std.testing.expect(sa.is_complete);
}

test "FEC-boundary guard (FD:544): clean small slot still completes (no regression)" {
    // Defense against over-rejection: a normal slot whose last shred sits on the
    // first FEC boundary (index 31, (31+1)%32 == 0) MUST still complete at 32
    // shreds. Proves the guard only withholds OFF-boundary last-flags.
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const dummy = [_]u8{0};

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, 1);
    defer sa.deinit();

    var i: u32 = 0;
    while (i < 31) : (i += 1) {
        try std.testing.expect(!(try sa.insert(i, &dummy, false)));
    }
    const completed = try sa.insert(31, &dummy, true); // on-boundary last
    try std.testing.expect(completed);
    try std.testing.expect(sa.is_complete);
    try std.testing.expectEqual(@as(?u32, 31), sa.last_index);
}

/// Build a minimal LEGACY (non-merkle) data shred wire buffer suitable for
/// getAssembledDataWithBoundaries: variant byte 0xA5 (legacy data), a
/// `flags` byte at offset 85, and a `data_size` (LE u16, includes the 88-byte
/// header) at offset [86..88] so total_size/boundary accounting works.
fn buildBoundaryTestShred(buf: []u8, flags: u8, entry_bytes: usize) void {
    @memset(buf, 0);
    buf[64] = 0xA5; // legacy data variant
    buf[85] = flags;
    std.mem.writeInt(u16, buf[86..88], @intCast(88 + entry_bytes), .little);
}

test "incident-422359406: DATA_COMPLETE (0x40) boundary on a FEC-recovered shred is NOT withheld (accepted, logged)" {
    // Two-component slot: component A ends mid-block at index 15 (0x40 alone,
    // OFF the 32-shred FEC boundary — legal; DATA_COMPLETE has no positional
    // invariant, unlike LAST_IN_SLOT). Component B ends the slot at index 31
    // (0xC0 = 0x40|0x80, ON the FEC boundary). Index 15 is marked `recovered`
    // (simulating a FEC-RS-reconstructed shred) to prove the boundary walk in
    // getAssembledDataWithBoundaries treats a recovered shred's 0x40 exactly
    // like a directly-received one — see the "incident-422359406" comment at
    // the boundary-detection site (getAssembledDataWithBoundaries, ~line 1853)
    // for why withholding it (mirroring the 0x80 guard) would be WRONG: 0x40
    // boundaries legitimately fall anywhere, so a positional/withhold guard
    // has no honest/spurious discriminator to lean on. The real corroboration
    // is the fec_resolver.zig #61 merkle root-gate at recovery time (verified
    // separately in fec_resolver.zig's own KATs).
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const slot_val: u64 = 900001;
    const entry_bytes: usize = 10; // arbitrary small per-shred payload

    const assembler = try ShredAssembler.initWithShredVersion(allocator, 0);
    defer assembler.deinit();

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, slot_val);
    try assembler.slots.put(slot_val, sa);

    var buf: [200]u8 = undefined;
    var idx: u32 = 0;
    while (idx < 32) : (idx += 1) {
        const flags: u8 = if (idx == 15) 0x40 else if (idx == 31) 0xC0 else 0x00;
        buildBoundaryTestShred(&buf, flags, entry_bytes);
        const is_last = (idx == 31);
        _ = try sa.insert(idx, buf[0 .. 88 + entry_bytes], is_last);
    }
    // Simulate index 15 having arrived via FEC recovery (the pull-in path),
    // NOT the direct network path — the exact provenance distinction the
    // incident postmortem found unlogged.
    sa.markRecovered(15);
    try std.testing.expect(sa.is_complete);

    const result = try assembler.getAssembledDataWithBoundaries(slot_val);
    defer allocator.free(result.data);
    defer allocator.free(result.boundaries);

    // Both boundaries present, in order, at the expected byte offsets —
    // component A = 16 shreds * 10B = 160B; component B = 32*10 = 320B total.
    try std.testing.expectEqual(@as(usize, 2), result.boundaries.len);
    try std.testing.expectEqual(@as(usize, 160), result.boundaries[0]);
    try std.testing.expectEqual(@as(usize, 320), result.boundaries[1]);
    try std.testing.expectEqual(@as(usize, 320), result.data.len);

    // Provenance bit is exactly index 15 — nothing else was marked recovered,
    // and the boundary walk did not consult it to decide inclusion (both
    // boundaries fired regardless of provenance).
    try std.testing.expect(sa.recovered.isSet(15));
    try std.testing.expect(!sa.recovered.isSet(14));
    try std.testing.expect(!sa.recovered.isSet(31));
}

test "incident-422359406: honest 0x40 on a directly-received (non-recovered) shred is unaffected" {
    // Baseline/regression: a slot with ONE mid-block boundary, no recovery
    // involved at all — must produce exactly the same boundary as before this
    // change (provenance tracking must be a strict no-op on this path).
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const slot_val: u64 = 900002;
    const entry_bytes: usize = 7;

    const assembler = try ShredAssembler.initWithShredVersion(allocator, 0);
    defer assembler.deinit();

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, slot_val);
    try assembler.slots.put(slot_val, sa);

    // Last shred MUST sit on the FEC boundary (index 31, (31+1)%32==0) or the
    // pre-existing 0x80 FEC-BOUNDARY-GUARD withholds it (by design — see the
    // "clean small slot still completes" test above) and the slot never
    // completes. Mid-block boundary at index 3 stays off-boundary on purpose
    // (0x40 has no positional invariant).
    var buf: [200]u8 = undefined;
    var idx: u32 = 0;
    while (idx < 32) : (idx += 1) {
        const flags: u8 = if (idx == 3) 0x40 else if (idx == 31) 0xC0 else 0x00;
        buildBoundaryTestShred(&buf, flags, entry_bytes);
        const is_last = (idx == 31);
        _ = try sa.insert(idx, buf[0 .. 88 + entry_bytes], is_last);
    }
    try std.testing.expect(sa.is_complete);

    const result = try assembler.getAssembledDataWithBoundaries(slot_val);
    defer allocator.free(result.data);
    defer allocator.free(result.boundaries);

    try std.testing.expectEqual(@as(usize, 2), result.boundaries.len);
    try std.testing.expectEqual(@as(usize, 4 * entry_bytes), result.boundaries[0]);
    try std.testing.expectEqual(@as(usize, 32 * entry_bytes), result.boundaries[1]);
    // Nothing was marked recovered anywhere in this slot.
    var i: u32 = 0;
    while (i < 32) : (i += 1) try std.testing.expect(!sa.recovered.isSet(i));
}

test "incident-422359406 follow-up: dumpSlotShredsWithProvenance round-trips index/provenance/boundaries/payload" {
    // Simulates the on-replay-failure forensic dump directly (the shred_assembler
    // half — replay_stage.zig's call site has no unit-test scaffold, same
    // reason Gate 2 in this incident's fix documented for fail.bin; this KAT
    // covers the part that IS unit-testable and carries all the new bytes).
    const allocator = std.testing.allocator;
    const SA = ShredAssembler.SlotAssembly;
    const slot_val: u64 = 900003;
    const entry_bytes: usize = 5;

    const assembler = try ShredAssembler.initWithShredVersion(allocator, 0);
    defer assembler.deinit();

    const sa = try allocator.create(SA);
    sa.* = SA.init(allocator, slot_val);
    try assembler.slots.put(slot_val, sa);

    var buf: [200]u8 = undefined;
    var idx: u32 = 0;
    while (idx < 32) : (idx += 1) {
        const flags: u8 = if (idx == 5) 0x40 else if (idx == 31) 0xC0 else 0x00;
        buildBoundaryTestShred(&buf, flags, entry_bytes);
        const is_last = (idx == 31);
        _ = try sa.insert(idx, buf[0 .. 88 + entry_bytes], is_last);
    }
    sa.markRecovered(5); // exactly one recovered index, matching the boundary
    try std.testing.expect(sa.is_complete);

    const result = try assembler.getAssembledDataWithBoundaries(slot_val);
    defer allocator.free(result.data);
    defer allocator.free(result.boundaries);
    try std.testing.expectEqual(@as(usize, 2), result.boundaries.len);

    assembler.dumpSlotShredsWithProvenance(slot_val, result.boundaries);

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/vex_slot_{d}_shreds.bin", .{slot_val});
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    defer std.fs.cwd().deleteFile(path) catch {};

    const bytes = try file.readToEndAlloc(allocator, 1 << 20);
    defer allocator.free(bytes);

    // Header.
    try std.testing.expectEqualSlices(u8, "VSD1", bytes[0..4]);
    try std.testing.expectEqual(@as(u8, 1), bytes[4]); // version
    try std.testing.expectEqual(slot_val, std.mem.readInt(u64, bytes[5..13], .little));
    var off: usize = 13;
    const num_boundaries = std.mem.readInt(u32, bytes[off..][0..4], .little);
    off += 4;
    try std.testing.expectEqual(@as(u32, 2), num_boundaries);
    var bi: u32 = 0;
    while (bi < num_boundaries) : (bi += 1) {
        const b = std.mem.readInt(u64, bytes[off..][0..8], .little);
        try std.testing.expectEqual(@as(u64, result.boundaries[bi]), b);
        off += 8;
    }
    const num_records = std.mem.readInt(u32, bytes[off..][0..4], .little);
    off += 4;
    try std.testing.expectEqual(@as(u32, 32), num_records);

    var seen_recovered_at: ?u32 = null;
    var ri: u32 = 0;
    while (ri < num_records) : (ri += 1) {
        const rec_idx = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const recovered = bytes[off];
        off += 1;
        const len = std.mem.readInt(u16, bytes[off..][0..2], .little);
        off += 2;
        const payload = bytes[off..][0..len];
        off += len;

        try std.testing.expectEqual(ri, rec_idx); // ascending, contiguous
        try std.testing.expectEqual(@as(usize, 88 + entry_bytes), payload.len);
        // Round-tripped flags byte matches what was inserted.
        const expect_flags: u8 = if (rec_idx == 5) 0x40 else if (rec_idx == 31) 0xC0 else 0x00;
        try std.testing.expectEqual(expect_flags, payload[85]);
        if (recovered == 1) {
            try std.testing.expectEqual(@as(?u32, null), seen_recovered_at); // exactly one
            seen_recovered_at = rec_idx;
        }
    }
    try std.testing.expectEqual(@as(?u32, 5), seen_recovered_at);
    try std.testing.expectEqual(bytes.len, off); // no trailing/missing bytes
}

/// Build a minimal LEGACY (non-merkle) data shred wire buffer for insertFrameWithFec
/// KATs. variant_byte=0xA5 (ShredType.data / fec_resolver.parseVariantByte legacy-data
/// exact match) keeps parsing trivial — no merkle proof geometry to worry about.
fn buildTestDataShred(buf: []u8, slot_val: u64, idx: u32, fec_set_index: u32) void {
    @memset(buf, 0);
    buf[64] = 0xA5; // legacy data variant byte
    std.mem.writeInt(u64, buf[65..73], slot_val, .little);
    std.mem.writeInt(u32, buf[73..77], idx, .little);
    std.mem.writeInt(u16, buf[77..79], 0, .little); // version
    std.mem.writeInt(u32, buf[79..83], fec_set_index, .little);
    std.mem.writeInt(u16, buf[83..85], 0, .little); // parent_offset
}

test "FIX 2026-07-07 (carrier 420258409): insertFrameWithFec DROPS a zero-copy frame on checksum mismatch, never inserts it" {
    // Reproduces the exact mechanism of carrier 420258409: the verify worker
    // checksums the shred payload right after sigverify (expected_cksum, computed
    // by the CALLER at verify_tile.zig:566 — a real zero-copy caller would recompute
    // this at copy time and see a DIFFERENT value if the NIC recycled the UMEM frame
    // mid-processing). We simulate that exact race by passing a deliberately WRONG
    // expected_cksum — no real NIC/AF_XDP needed, this is a pure function-level KAT
    // of the branch shred.zig:1242-1261 takes on mismatch.
    //
    // PRE-FIX behavior: logs [FRAME-OVERWRITE] then FALLS THROUGH into
    // fec_resolver.addShred + assembly.insert — this test's assertions
    // (slots.get(slot_val) == null, return value == .dropped_frame_overwrite,
    // frame_overwrite_dropped counter == 1) FAIL on that old code path (assembly
    // would contain the shred; return would be .inserted; counter field didn't exist).
    // POST-FIX: the frame is dropped before touching the FEC resolver or assembly.
    const allocator = std.testing.allocator;
    const assembler = try ShredAssembler.init(allocator);
    defer assembler.deinit();

    const test_slot: u64 = 999_888_777;
    var buf: [200]u8 = undefined;
    buildTestDataShred(&buf, test_slot, 0, 0);
    const s = try parseShred(&buf);

    // frame_manager stays null (default) — insertFrameWithFec's release-defer is a
    // no-op, so no real UmemFrameManager/AF_XDP mock is required for this KAT.
    const fake_frame = UmemFrameRef{
        .frame_addr = 0,
        .data = &buf,
        .len = @intCast(buf.len),
    };

    const correct_cksum = std.hash.Wyhash.hash(0, s.payload);
    const wrong_cksum = correct_cksum ^ 0xDEAD_BEEF_1234_5678;

    // 1. MISMATCH: must DROP, not insert.
    const dropped_result = try assembler.insertFrameWithFec(s, fake_frame, wrong_cksum);
    try std.testing.expectEqual(ShredAssembler.InsertResult.dropped_frame_overwrite, dropped_result);
    try std.testing.expectEqual(@as(u64, 1), assembler.frame_overwrite_dropped.load(.monotonic));
    // Decisive: the corrupted bytes must NEVER have reached the data-shred assembly.
    try std.testing.expect(assembler.slots.get(test_slot) == null);

    // 2. MATCH (same shred, correct cksum): must proceed normally and actually insert —
    // proves the fix only short-circuits the MISMATCH path, not the whole function.
    const inserted_result = try assembler.insertFrameWithFec(s, fake_frame, correct_cksum);
    try std.testing.expect(inserted_result == .inserted or inserted_result == .completed_slot);
    try std.testing.expectEqual(@as(u64, 1), assembler.frame_overwrite_dropped.load(.monotonic)); // unchanged
    const assembly = assembler.slots.get(test_slot) orelse return error.ExpectedAssemblyPresent;
    try std.testing.expect(assembly.contains(0));

    // 3. expected_cksum==0 (the kernel-UDP / non-zero-copy convention, tvu.zig:1672)
    // must SKIP the check entirely even with a "wrong" real checksum — a second,
    // distinct shred proves this without colliding with the assembly built above.
    var buf2: [200]u8 = undefined;
    buildTestDataShred(&buf2, test_slot, 1, 0);
    const s2 = try parseShred(&buf2);
    const fake_frame2 = UmemFrameRef{ .frame_addr = 0, .data = &buf2, .len = @intCast(buf2.len) };
    const skip_result = try assembler.insertFrameWithFec(s2, fake_frame2, 0);
    try std.testing.expect(skip_result == .inserted or skip_result == .completed_slot);
    try std.testing.expectEqual(@as(u64, 1), assembler.frame_overwrite_dropped.load(.monotonic)); // still unchanged
}
