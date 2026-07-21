//! Vexor TVU (Transaction Validation Unit)
//!
//! Handles shred reception, repair, and replay coordination.
//! Uses UDP (NOT QUIC) for shreds - optimal for small packets with erasure coding.
//!
//! Pipeline:
//! 1. Receive shreds via AF_XDP (kernel bypass) or UDP fallback
//! 2. Verify shred signatures (parallel/batched)
//! 3. Insert into shred assembler
//! 4. Request repairs for missing shreds
//! 5. Trigger replay when slots complete
//!
//! Performance notes:
//! - AF_XDP: ~10M pps (kernel bypass)
//! - Standard UDP: ~1M pps
//! - QUIC would be slower due to protocol overhead

const std = @import("std");
const core = @import("core");
const build_options = @import("build_options"); // Phase 9: legacy_pins escape hatch
const vex_ledger_mod = @import("vex_ledger"); // VexLedger persistent blockstore (flag-gated persist tap)
const ledger_tile_mod = @import("ledger_tile.zig"); // MPSC ring + cold-core tile (moves ledger I/O off the hot path)
const vex_topo = @import("vex_topo"); // Phase 9: declarative tile→core topology table
const packet = @import("packet.zig");
const socket = @import("socket.zig");
pub const gossip = @import("gossip.zig");
pub const snapshot_trust = @import("snapshot_trust.zig"); // A3b: known-validator snapshot-hash agreement (main.zig pre-vote gate uses vex_network.snapshot_trust)
const runtime = @import("vex_svm");
const consensus = @import("vex_consensus");
const storage = @import("vex_store");
const accelerated_io = @import("accelerated_io.zig");
const shared_xdp = @import("af_xdp/shared_xdp.zig");
pub const af_xdp = @import("af_xdp/socket.zig");
pub const shred_pub = @import("shred.zig");
pub const slot_chain_tracker = @import("slot_chain_tracker.zig");
const shred_mod = @import("shred.zig");
const cluster_slots_mod = @import("cluster_slots.zig");
const repair_targeting = @import("repair_targeting.zig");
const weighted_shuffle = @import("weighted_shuffle.zig"); // repair stake-weighting (gated -Drepair_stake_weighting)
const repair_escalate = @import("repair_escalate.zig"); // FIX #3 phantom-wedge escalation predicate (pure, KAT-tested)
const repair_abandon = @import("repair_abandon.zig"); // 2026-07-04 cluster-skip ABANDON mutation (extracted + KAT-tested)
const repair_inflight = @import("repair_inflight.zig"); // @prov:tvu.repair-inflight — VEX_REPAIR_INFLIGHT pacing lever, KAT-tested
const turbine_relay = @import("turbine_relay.zig");
const shred_header = @import("shred_header.zig"); // C1: per-shred on-wire (variant/index) parse for getBroadcastPeer
const orphan_request = @import("orphan_request.zig"); // orphan-repair (2026-05-30): byte-exact Orphan(disc=10) request builder
pub const verify_tile = @import("verify_tile.zig");
pub const rpc = @import("rpc.zig");
pub const rpc_methods = @import("rpc_methods.zig"); // SB-2 (2026-06-17): expose the RPC method registry + RpcContext so the rpc-history wiring KATs can drive the handlers via the vex_network module boundary
pub const geyser = @import("geyser.zig"); // Geyser streaming sink (2026-06-22): GeyserService wired in main.zig under -Dgeyser + VEX_GEYSER
// task #13 LOOPBACK: QUIC TPU ingest server + the QUIC→mempool adapter, re-exported so main.zig can
// reference the types from the vex_network module (previously reachable only in the test-quic-ingest
// test build). Gated at the call site by VEX_TPU_INGEST (default OFF) — these `pub const`s add no
// runtime behavior on their own.
pub const solana_quic = @import("solana_quic.zig");
pub const tpu_client = @import("tpu_client.zig");
pub const quic_ingest_adapter = @import("quic_ingest_adapter.zig");

// Repair-serve token bucket (DoS flood backstop). Defined in its own std-only file
// so the KAT (test-repair-ratelimit) can drive it in isolation without dragging the
// whole tvu.zig dependency graph. See repair_token_bucket.zig for the full rationale.
pub const RepairTokenBucket = @import("repair_token_bucket.zig").RepairTokenBucket;

// ── SlotSink: the seam between tvu and the replay stage (Phase B.2, 2026-07-08) ──
// tvu no longer holds a raw *ReplayStage; it holds a type-erased SlotSink exposing
// ONLY the narrow surface it uses (4 methods + 2 field accessors). This decouples
// the network layer from the replay god-file — Phase C can relocate ReplayStage's
// internals (incl. root_bank / accounts_db) without touching tvu — and it enforces
// the TVU no-cross-thread-sync rule at the type boundary. Behavior-identical to the
// direct pointer (pure indirection). `ReplayStage.slotSink()` builds one.
pub const SlotSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        pushSlotForReplayWithBoundaries: *const fn (*anyopaque, core.Slot, []u8, []const usize) bool,
        collectOrphanTargets: *const fn (*anyopaque, std.mem.Allocator, usize) anyerror![]u64,
        fetchProducedSlots: *const fn (*anyopaque, u64, u64) ?[]u64,
        setShredAssembler: *const fn (*anyopaque, *shred_pub.ShredAssembler) void,
        rootBank: *const fn (*anyopaque) ?*runtime.Bank, // does .load(.acquire) inside
        accountsDb: *const fn (*anyopaque) ?*storage.accounts.AccountsDb,
        // fix/chain-defer-tip-guard: atomically take+clear a continuation slot the
        // CHAIN-WAKE fallback needs repaired (0 ⇒ none). Lock-free swap inside.
        takeContinuationRepair: *const fn (*anyopaque) ?core.Slot,
    };

    pub fn pushSlotForReplayWithBoundaries(self: SlotSink, slot: core.Slot, data: []u8, boundaries: []const usize) bool {
        return self.vtable.pushSlotForReplayWithBoundaries(self.ctx, slot, data, boundaries);
    }
    pub fn collectOrphanTargets(self: SlotSink, allocator: std.mem.Allocator, max: usize) anyerror![]u64 {
        return self.vtable.collectOrphanTargets(self.ctx, allocator, max);
    }
    pub fn fetchProducedSlots(self: SlotSink, lo: u64, hi: u64) ?[]u64 {
        return self.vtable.fetchProducedSlots(self.ctx, lo, hi);
    }
    pub fn setShredAssembler(self: SlotSink, sa: *shred_pub.ShredAssembler) void {
        self.vtable.setShredAssembler(self.ctx, sa);
    }
    pub fn rootBank(self: SlotSink) ?*runtime.Bank {
        return self.vtable.rootBank(self.ctx);
    }
    pub fn accountsDb(self: SlotSink) ?*storage.accounts.AccountsDb {
        return self.vtable.accountsDb(self.ctx);
    }
    pub fn takeContinuationRepair(self: SlotSink) ?core.Slot {
        return self.vtable.takeContinuationRepair(self.ctx);
    }
};

// ── CPU pinning helper ───────────────────────────────────────────────────────

fn pinToCore(core_id: u32) void {
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
    std.log.debug("[PIN] Thread pinned to core {d}\n", .{core_id});
}

// jemalloc control interface (non-prefixed symbol, DT_NEEDED libjemalloc).
extern fn mallctl(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;

/// 2026-06-14 CONFIRMED FIX for the constant ~212ms AF_XDP recv stall: bind the
/// CALLING thread to a DEDICATED jemalloc arena. The recv thread's hot-path
/// allocations (FEC shred buffers, repair PacketBatch, chain-tracker) were blocking
/// on the SHARED arena mutex held by a peer thread (verify/replay/SVM) mid-alloc —
/// proven by gdb (alloc → __pthread_mutex_lock → futex_wait) + nonvoluntary_ctxt=0
/// (NOT preemption). A private arena (touched only by this single thread) has ZERO
/// lock contention. No behavior/consensus change — only allocation locality.
fn bindDedicatedArena() void {
    var arena_id: c_uint = 0;
    var sz: usize = @sizeOf(c_uint);
    if (mallctl("arenas.create", &arena_id, &sz, null, 0) != 0) {
        std.log.warn("[RECV-ARENA] arenas.create failed — recv stays on shared arena (lock contention possible)", .{});
        return;
    }
    if (mallctl("thread.arena", null, null, &arena_id, @sizeOf(c_uint)) != 0) {
        std.log.warn("[RECV-ARENA] thread.arena set failed for arena {d}", .{arena_id});
        return;
    }
    std.log.warn("[RECV-ARENA] TVU recv thread bound to DEDICATED jemalloc arena {d} (no shared arena-lock contention)", .{arena_id});
}

/// FIX #3 (2026-06-14): is the AF_XDP phantom-index restart FLOOR enabled?
/// Default ON; set VEX_REPAIR_STUCK_FAILSTOP=0 to disable (stay up). Read ONCE
/// from the environment and cached (same read-once pattern as VEX_LOG_INFO /
/// VEX_DEBUG_ALLOC) so it is not parsed on every repair iteration. Uses
/// std.posix.getenv (honored under AT_SECURE, unlike getenv with file caps).
fn repairStuckFailstopEnabled() bool {
    const S = struct {
        var init = std.once(resolve);
        var enabled: bool = true;
        fn resolve() void {
            if (std.posix.getenv("VEX_REPAIR_STUCK_FAILSTOP")) |v| {
                // Enabled unless explicitly "0" / "false" / "off".
                enabled = !(std.mem.eql(u8, v, "0") or
                    std.mem.eql(u8, v, "false") or
                    std.mem.eql(u8, v, "off"));
            } else {
                enabled = true; // default ON
            }
        }
    };
    S.init.call();
    return S.enabled;
}

/// 2026-07-04: is the oracle-guarded INVERSE-SKIP path enabled? DEFAULT OFF;
/// set VEX_REPAIR_SKIP_ABANDONED=1 to arm. When UNSET/"0" the entire abandon
/// path in checkAndRequestRepairs is inert (byte-identical to the prior
/// HWI-rederive → fail-stop behavior). Read ONCE + cached, exactly like
/// repairStuckFailstopEnabled (same std.posix.getenv AT_SECURE-honored read).
///
/// This gates the fix for the 12h repair-wedge carrier: a slot the CLUSTER
/// SKIPPED (partial shreds, is_full=false; canonical chain routes AROUND it) is
/// treated by Vexor as a mandatory contiguous bridge → the repair loop fixates
/// on it forever and eventually fail-stops. When ON, if — and ONLY if — the
/// cluster oracle CONFIRMS the skip (repair_escalate.clusterConfirmedSkip), the
/// slot is dropped from the in-progress + repair set (Agave set_root /
/// prune_non_rooted analog) instead of fail-stopping. Default OFF because the
/// abandon decision is consensus-adjacent — the exact code area whose earlier
/// Phase-J variant false-positived on forked validators in May 2026; it is armed
/// only after an offline-replay gate.
fn repairSkipAbandonedEnabled() bool {
    const S = struct {
        var init = std.once(resolve);
        var enabled: bool = false;
        fn resolve() void {
            if (std.posix.getenv("VEX_REPAIR_SKIP_ABANDONED")) |v| {
                // OFF by default; armed only for explicit "1" / "true" / "on".
                enabled = std.mem.eql(u8, v, "1") or
                    std.mem.eql(u8, v, "true") or
                    std.mem.eql(u8, v, "on");
            } else {
                enabled = false; // default OFF
            }
        }
    };
    S.init.call();
    return S.enabled;
}

/// UMEM frame count used by BOTH accelerated-IO construction sites
/// (tryStartAcceleratedIO / tryStartAcceleratedIOFallback, ~tvu.zig:1317,1371).
/// RC7 (AFXDP-REWORK-PLAN-2026-06-11.md, "D4 — SPSC free-ring used MPMC": the
/// non-atomic free_ring head reservation that 8 verify workers + TVU + sweeper
/// could race on) was the actual mechanism behind the 2026-05-28 "PID 3214488
/// Sweeper head corruption" that forced a 131072→32768 revert. RC7 was FIXED
/// 2026-06-13 (commit 219fc32, `UmemFrameManager.release`/`replenishFillRing`
/// now serialize free_ring enqueue/dequeue under `free_mutex` — see the D4
/// comment on `release()` above). Verified: 219fc32 predates and is an
/// ancestor of this HEAD, i.e. the fix has been live/soaked since 06-13 with
/// no recurrence — the regrow blocker is gone.
///
/// RE-GROWN 2026-07-07 (task #42 rxshed-tune follow-up): measured evidence
/// (see umemReserveFrames() below) showed the pool was NOT merely "shedding
/// too eagerly at a conservative threshold" — freeDepth() sat at literal 0 in
/// 74.2% of 1Hz [AFXDP-PHASE] samples over a 74-minute live window REGARDLESS
/// of reserve (varying the threshold from 2048 down to 1 only moved the
/// shed-trigger rate 81.2%→74.2%), while frames_held (the actual verify-
/// pipeline in-flight population the shed gate exists to protect) stayed ~0
/// the entire time (max 398, p99.9=309 over 4275 samples) — i.e. genuine
/// kernel-level exhaustion ([AFXDP-PHASE] kfill_empty grew from 16→178,004 in
/// the same window), not a threshold miscalibrated against a healthy resting
/// level. Only fill_size (still 16384, unchanged — see the two call sites
/// below) governs the kernel Fill Ring/RX Ring sizing that caused past
/// reverts; growing frame_count only deepens the software recycle reservoir
/// (free_ring), so this does not reopen the "fill must be < frame_count"
/// class of bug (16384 << 131072).
const UMEM_FRAME_COUNT_DEFAULT: u32 = 131072;

/// UMEM backpressure reserve (2026-07-07, task #42 rxshed-tune correction):
/// the low-water mark on the recycle-reservoir depth (UmemFrameManager.
/// freeDepth()) below which the recv path SHEDS new frames instead of handing
/// them to the verify pipeline (see UmemFrameManager.shouldShed in
/// af_xdp/socket.zig).
///
/// CORRECTED default: a small FIXED constant, deliberately NOT a fraction of
/// frame_count. The prior formula (`max(1024, frame_count/16)` = 2048 of
/// 32768) was the root defect: it scaled with pool size instead of with the
/// actual protected quantity (frames_held, the verify-pipeline in-flight
/// population an overwrite would corrupt) — and would have gotten 4x WORSE
/// (8192) under the 2026-07-07 frame_count regrow above if left as a
/// fraction. Firedancer's canonical fd_xsk/net_tile idiom carries NO reserve
/// at all (a frame is "immediately sent to the FILL ring" on reuse —
/// net_tile.md "FILL ring" section; FD's backpressure is entirely the
/// downstream mcache credit system in fd_stem.c, not a UMEM low-water mark).
/// Vexor keeps a small non-zero cushion (unlike FD) because the recv loop
/// cannot yet replicate FD's per-consumer credit accounting in one patch —
/// 256 sits comfortably above the measured max frames_held burst (398, but
/// held and free_depth are disjoint pools; 256 is cushion against the sample-
/// to-sample gap, not a per-held-frame budget) while being ~8x smaller than
/// the old 2048 and, critically, INDEPENDENT of frame_count so a future pool
/// regrow doesn't silently multiply the shed rate again. Matches the
/// VEX_UMEM_RESERVE=256 emergency interim value already applied live
/// 2026-07-07 (this makes it the permanent code default, not just an env
/// override). VEX_UMEM_RESERVE still overrides it (any positive integer);
/// malformed/zero values fall back to the default rather than disabling the
/// gate silently. Read ONCE + cached (same std.once pattern as
/// repairStuckFailstopEnabled) since env parsing on every received frame
/// would defeat the "cheap atomic load" requirement.
fn umemReserveFrames() u32 {
    const S = struct {
        var init = std.once(resolve);
        var reserve: u32 = 0;
        fn resolve() void {
            const default_reserve: u32 = 256;
            reserve = default_reserve;
            if (std.posix.getenv("VEX_UMEM_RESERVE")) |v| {
                const trimmed = std.mem.trim(u8, v, " \t\r\n");
                if (std.fmt.parseInt(u32, trimmed, 10) catch null) |n| {
                    if (n > 0) reserve = n;
                }
            }
        }
    };
    S.init.call();
    return S.reserve;
}

/// TVU service for shred processing
pub const TvuService = struct {
    allocator: std.mem.Allocator,

    /// High-performance I/O for shreds (AF_XDP when available)
    shred_io: ?*accelerated_io.AcceleratedIO,

    /// High-performance I/O for repairs
    repair_io: ?*accelerated_io.AcceleratedIO,

    /// Shared XDP manager (for multi-socket AF_XDP)
    xdp_manager: ?*shared_xdp.SharedXdpManager,

    /// Legacy UDP socket for shreds (fallback)
    shred_socket: ?socket.UdpSocket,

    /// Legacy UDP socket for repairs (fallback)
    repair_socket: ?socket.UdpSocket,

    /// Port configuration
    tvu_port: u16,
    tvu_fwd_port: u16,
    repair_port: u16,

    /// Shred assembler
    shred_assembler: *shred_mod.ShredAssembler,

    /// Reference to ledger DB
    ledger_db: ?*storage.LedgerDb,

    /// Reference to leader schedule
    leader_cache: ?*consensus.leader_schedule.LeaderScheduleCache,

    /// Reference to gossip service for repair peer discovery
    gossip_service: ?*gossip.GossipService,
    /// Reference to replay stage for slot processing
    slot_sink: ?SlotSink, // Phase B.2 seam: was ?*runtime.replay_stage.ReplayStage
    /// Optional VexLedger persistent blockstore (flag-gated shadow-write of completed
    /// slots). Null unless built with -Dvex_ledger AND the VEX_LEDGER env is set.
    /// Defaulted so the struct-literal init in `init` can omit it.
    vex_ledger: ?*vex_ledger_mod.VexLedger = null,
    // When set (alongside vex_ledger), the completion path ENQUEUES to this tile
    // instead of writing inline — the tile does putShred/finishSlot+fsync on a
    // cold core, off the consensus completion threads. Wired from main.zig.
    ledger_tile: ?*ledger_tile_mod.LedgerTile = null,
    ledger_tile_thread: ?std.Thread = null,
    /// Optional override for repair peers (testing)
    repair_peers_override: std.ArrayListUnmanaged(RepairPeer),
    /// Guards getRepairPeers' shared sampling statics + repair_peers_override
    /// reads. Stage 1 adds a second caller of getRepairPeers (the core-30 repair
    /// control tile) concurrent with the recv thread's seedCatchupRepairs path;
    /// the full-body lock makes the build+sample atomic (no torn statics, no
    /// divide-by-zero between the all_peer_count guard and the modulo).
    repair_peers_mutex: std.Thread.Mutex = .{},

    /// SLOT-AWARE REPAIR (2026-06-14): bounded slot->{advertiser peers} index.
    /// Fed by EpochSlots gossip ingest (gossip.zig handlePush/handlePullResponse,
    /// cross-linked via gossip.setClusterSlots at wiring time); read by
    /// getRepairPeers to PREFER peers that advertise the requested slot; pruned by
    /// setRoot at the repair root-advance cadence. Has its OWN mutex (independent
    /// of repair_peers_mutex and the gossip contacts_rw lock). Repair-targeting
    /// metadata only — NEVER feeds bank_hash / consensus / shred validation.
    cluster_slots: cluster_slots_mod.ClusterSlots,

    /// Stage 1 (2026-06-14, AF_XDP net-tile decouple): dedicated repair/control
    /// tile pinned to CORE 30. When AF_XDP zero-copy is the active backend, the
    /// three repair-control blocks (repair cycle, orphan repair, proactive repair)
    /// run on this tile instead of inline on the recv loop (core 4) so the named
    /// ~200ms checkrep/orphan/proactive spikes can no longer starve the XSK fill
    /// ring. Gated on config.enable_af_xdp && config.xdp_zero_copy (same gate as
    /// the recv zero-copy / verify-handoff path). When the gate is OFF (kernel-UDP
    /// voting node) repair_tile_active stays false and the three blocks run inline
    /// byte-identically to today.
    repair_tile_thread: ?std.Thread = null,
    repair_tile_active: bool = false,

    /// VEX_REPAIR_SKIP_ABANDONED getBlocks throttle cache (default OFF path).
    /// The oracle-guarded INVERSE-SKIP abandon check queries the cluster's
    /// getBlocks (is_skipped) list for the stuck slot's [X-16, X+16] neighborhood
    /// AT MOST once per 30s per stuck slot; the result is cached here and reused
    /// within the window (no per-repair-cycle RPC spam). Touched ONLY by
    /// checkAndRequestRepairs, which runs on EXACTLY ONE thread by construction
    /// (recv-thread inline XOR the core-30 repair tile, gated on
    /// repair_tile_active) — so these fields need no mutex.
    ///   skip_canon_slot:      the stuck slot X the cached list is for (0 = none).
    ///   skip_canon_query_ns:  wall-clock ns of the last getBlocks query.
    ///   skip_canon_produced:  owned produced-slot list for [X-16, X+16], or null
    ///                         if the last query FAILED (fail-closed → no abandon).
    skip_canon_slot: u64 = 0,
    skip_canon_query_ns: u64 = 0,
    skip_canon_produced: ?[]u64 = null,

    /// Running state
    running: std.atomic.Value(bool),

    /// Slots pending replay (guarded by pending_slots_mutex)
    pending_slots: std.ArrayListUnmanaged(core.Slot),
    pending_slots_mutex: std.Thread.Mutex,

    /// Statistics
    stats: Stats,

    /// Configuration
    config: Config,

    /// Whether using accelerated I/O
    using_accelerated_io: bool,

    /// Turbine tree for shred propagation
    turbine: Turbine,

    /// turbine-retransmit (gated): runtime arm for the outbound retransmit of received
    /// shreds to tree children. Comptime-gated by build_options.turbine_retransmit AND
    /// armed at init from the VEX_TURBINE_RETRANSMIT env. When the comptime flag is OFF
    /// this field is still present but never read (the call site is `comptime` dead).
    turbine_retransmit_armed: bool = false,

    /// repair-serve rate limiter (defensive flood backstop). Token bucket over response
    /// bytes; default-active with a generous limit (VEX_REPAIR_RATELIMIT_MBPS, default
    /// 100 MB/s). @prov:tvu.repair-ratelimit Only drops under extreme load. Guards
    /// ONLY outbound repair RESPONSES (sendRepairResponse); ping/pong is exempt. Never
    /// touches consensus. mutex guards the bucket because the serve path may run on
    /// either the repair drain thread or kernel-UDP fallback.
    repair_bucket: RepairTokenBucket,
    repair_bucket_mutex: std.Thread.Mutex = .{},

    /// Last repair request timestamp (for throttling)
    last_repair_time_ns: u64,
    last_turbine_update_ns: u64,
    last_diag_ns: u64,
    start_time_ns: u64,

    /// Repair request dedup cache (matches Firedancer's dedup design)
    /// Key: (slot << 32) | shred_idx, Value: timestamp_ns of last request
    /// Prevents re-requesting the same (slot, idx) within REPAIR_DEDUP_TIMEOUT_NS
    repair_dedup: std.AutoHashMap(u128, u64),

    /// d27k (2026-05-11): turbine-seeded catchup watermark.
    /// Set on the FIRST turbine shred ever received in processShred to that
    /// shred's slot. Until set: sentinel = std.math.maxInt(u64).
    /// @prov:tvu.turbine-slot0 — mirrors the "first turbine shred" boundary
    /// concept. The
    /// gap `(catchup_root_slot, turbine_slot0]` is what catchup must
    /// close — this is the canonical pattern in both validators per
    /// the 2026-05-11 architecture investigation (memory: project_d27k_*).
    turbine_slot0: std.atomic.Value(u64) = std.atomic.Value(u64).init(std.math.maxInt(u64)),

    /// d27k: snapshot root slot — bootstrap entrypoint into the chain.
    /// Set once via `setCatchupRoot` after snapshot load.
    catchup_root_slot: u64 = 0,

    /// d27k: timestamp of last `seedCatchupRepairs` burst (ms). The seed
    /// is re-fireable: gossip table grows over the first ~60s of startup
    /// (70 → 100 → 200 → 500+), so a one-shot burst at first turbine shred
    /// would only reach the ~70 peers known at that instant. Re-firing
    /// every N seconds lets the burst reach more peers as gossip warms.
    /// CAS-guarded so only one thread re-fires per throttle window.
    last_catchup_seed_fire_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    /// Companion catch-up lever (VEX_CATCHUP_ADAPTIVE_REFIRE, default OFF).
    /// When true, seedCatchupRepairs shortens the refire interval from the fixed
    /// 30s toward a 5s floor as the gap (turbine_slot0 - consensus_root) grows,
    /// cutting deep-gap discovery latency. Default false ⇒ cadence stays 30s ⇒
    /// byte-identical to the current voting binary. Per-fire dispatch budget is
    /// UNCHANGED — identical bursts, just more of them. NO persistent cursor.
    catchup_adaptive_refire: bool = false,

    /// ── REPAIR-INFLIGHT pacing lever (VEX_REPAIR_INFLIGHT, default OFF) ──────
    /// @prov:tvu.repair-inflight — 2026-07-06. When armed: every type-8 WindowIndex
    /// request carries a
    /// UNIQUE nonce from a monotonic tile-owned counter and is recorded in the
    /// fixed-pool inflight table; a returning repair shred is nonce+slot+idx
    /// matched back to its request (RTT + per-peer credit); requests older
    /// than VEX_REPAIR_TIMEOUT_MS (default 150ms; FD uses 80ms) are drained head-of-FIFO
    /// and the still-missing shreds re-requested IMMEDIATELY from a rotated
    /// DIFFERENT peer (bypassing the 200ms dedup TTL). Peer-scoring lite
    /// (req/res/RTT per pubkey) then steers getRepairPeers away from dead
    /// peers and toward fast ones. ALL of it is advisory repair pacing —
    /// ingest/validation is unchanged in both gate states; unset ⇒ every
    /// branch below is dead ⇒ byte-identical current behavior.
    ///
    /// THREADING: inflight table + nonce counter + peer_scores are owned by
    /// the repair tile thread (AF_XDP: send in checkAndRequestRepairs and
    /// response in drainRepairPackets both run on the core-30 tile; kernel-UDP
    /// fallback: both run inline on the recv thread — same-thread either way,
    /// repair_tile_active gates exactly one driver). NO new cross-thread sync.
    repair_inflight_enabled: bool = false,
    /// Fixed-pool inflight table (heap-allocated ONCE at init when armed;
    /// null when the gate is off — no memory cost for the default path).
    inflight: ?*repair_inflight.InflightTable = null,
    /// Monotonic per-request nonce (tile-owned; wrap is safe — the table
    /// evicts a stale same-nonce entry and remove() verifies slot+idx).
    inflight_nonce: u32 = 0,
    /// Re-request timeout (VEX_REPAIR_TIMEOUT_MS, default 150ms).
    inflight_timeout_ns: i64 = 150 * std.time.ns_per_ms,
    /// Peer-scoring lite: pubkey -> {requests sent, responses matched, total
    /// RTT}. Capacity reserved at init (no hot-path allocation); when full,
    /// unseen peers simply go unscored (fail-open).
    peer_scores: std.AutoHashMapUnmanaged([32]u8, PeerScore) = .empty,
    /// [REPAIR-INFLIGHT] stats (tile-owned, plain fields — same thread).
    inflight_rerequests: u64 = 0,
    inflight_fills_matched: u64 = 0,
    inflight_rtt_sum_ns: u64 = 0,
    inflight_rtt_cnt: u64 = 0,
    inflight_last_stats_ns: i128 = 0,
    /// Rotation cursor so successive timeout re-requests walk DIFFERENT peers.
    inflight_rerequest_rot: u64 = 0,

    /// FIX B2 (2026-06-14, AF_XDP catch-up wedge diagnostics — LOG ONLY).
    /// Single bounded stuck-slot tracker (NOT an unbounded map): when
    /// checkAndRequestRepairs detects the lowest in-progress slot has a small
    /// missing set (<=4) it records that slot here, the first-seen timestamp,
    /// and how many repair requests it has issued for it; processRepairResponse
    /// increments `..._resp_count` when an arriving repair shred matches the
    /// tracked slot. Lets us answer "do peers ANSWER for that specific stuck
    /// index?" without any per-slot map. Reset whenever the lowest-slot identity
    /// changes. All atomics, all advisory — zero behavior/consensus impact.
    stuck_slot: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stuck_slot_since_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),
    stuck_slot_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stuck_slot_resp_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stuck_slot_last_warn_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),
    /// FIX #3 (2026-06-14, AF_XDP phantom-index wedge — bounded-retry → restart
    /// FLOOR, Agave #28596 MAX_REPAIR_RETRY_LOOP_ATTEMPTS analog). When the SAME
    /// lowest-in-progress slot stays shred-short for a conservative wall-clock
    /// window with a SMALL missing set, many requests sent, and ~0 responses FOR
    /// that slot (the phantom-index signature: nobody cluster-wide has the index
    /// we're asking for, because our knows_last/last_shred_index is wrong), we
    /// escalate: (a) fire a HighestWindowIndex to RE-DERIVE the true completion
    /// bound from peers (corrects a dropped-LAST phantom when last_index is null),
    /// then (b) as the absolute floor, a CLEAN env-gated fail-stop so the
    /// operator's fresh-snapshot restart recovers — NEVER skip/abandon the slot.
    /// last_hwi_rederive_ns throttles (a); failstop_armed_since_ns records when
    /// the escalation criterion first held continuously for THIS slot.
    stuck_slot_last_hwi_rederive_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),
    stuck_slot_failstop_armed_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),
    /// FIX #3: progress watermark for the tracked stuck slot — the highest
    /// unique_count seen, plus when it last advanced. Makes the fail-stop
    /// discriminator PROGRESS-based (no new shred lands for the slot over the
    /// window) rather than purely response-count based, so it stays robust for
    /// MIXED wedges (real interior gaps that DO get answered — inflating the
    /// cumulative resp count — combined with an unfillable phantom tail). "No
    /// progress despite many requests" is the true wedge signal and is immune to
    /// historical gap-fill inflation. Reset on stuck-slot identity change.
    stuck_slot_progress_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stuck_slot_progress_ns: std.atomic.Value(i128) = std.atomic.Value(i128).init(0),

    /// Last time the dedup cache was pruned (to prevent unbounded growth)
    last_dedup_cleanup_ns: u64,

    /// Our validator identity (for Turbine)
    identity: ?core.Pubkey,

    /// Thread pool for parallel retransmission
    thread_pool: std.Thread.Pool,

    /// Turbine Relay stage for forwarding shreds
    retransmit_stage: turbine_relay.TurbineRelay,

    /// Receive thread handle (for join on shutdown)
    receive_thread: ?std.Thread = null,

    /// Consensus tracker for diagnostic tracing
    consensus_tracker: ?*anyopaque = null,

    /// Verify Tile: cryptographic signature verification pipeline
    verify_tile_instance: ?*verify_tile.VerifyTile = null,

    /// Option A (2026-06-14): recv-local staging ring for zero-copy frames that
    /// hit a `.contended` verify-queue submit (a worker holds queue.mutex). The
    /// recv thread NEVER blocks on the mutex (the 212ms lock-convoy that wedged
    /// AF_XDP catch-up); it parks the frame here and re-tries each loop. Single
    /// thread (recv) only — NO atomics needed. Lazily heap-allocated on first use.
    staging_buf: ?[]StagingEntry = null,
    staging_head: u32 = 0, // next write
    staging_tail: u32 = 0, // next read
    staging_overrun: u64 = 0, // frames dropped because staging was full
    staging_depth_max: u32 = 0, // high-water mark (for [AFXDP-PHASE])

    /// UMEM backpressure reserve (2026-07-07, task #42 option (c)): the
    /// low-water mark on the recycle-reservoir depth, resolved ONCE at init
    /// from VEX_UMEM_RESERVE (see umemReserveFrames()). Checked via a single
    /// cheap atomic load (UmemFrameManager.shouldShed) at the recv→verify
    /// handoff in processPackets(); recv-thread-only, read-only after init.
    umem_reserve: u32 = 0,

    /// [AFXDP-POOL-LOW] rate-limit state (recv-thread-only, single-writer —
    /// same threading model as the ins_* 1Hz instrumentation locals in run()).
    /// Counts consecutive 1Hz samples where free_depth==0 so the alarm logs
    /// first occurrence + every 1000th + a one-shot "recovered" line, instead
    /// of one line per second indefinitely (thousands over a sustained spiral).
    pool_low_streak: u64 = 0,

    /// 2026-06-14 ROOT FIX: reusable PacketBatch buffers (allocated ONCE, cleared
    /// per use) for the kernel-shred-socket drain + repair drain. Previously each
    /// processPackets() loop did `PacketBatch.init` (a ~768KB alloc for 512×1500B
    /// Packets) + deinit EVERY iteration — at ~6800 loops/s that is ~5 GB/s of
    /// alloc+free churn through jemalloc's large-allocation/extent path, which
    /// serializes on global locks and caused the constant ~212ms recv stall (gdb:
    /// alloc → pthread_mutex_lock → futex_wait) that wedged AF_XDP catch-up. The
    /// dedicated arena didn't help because large allocs bypass per-arena bins. Reuse
    /// eliminates the churn entirely. Lazily allocated; recv-thread-only.
    recv_batch: ?packet.PacketBatch = null,
    repair_batch_reuse: ?packet.PacketBatch = null,
    /// Stage 2 (2026-06-17): tile-local repair batch so the core-30 repair tile
    /// drains repair packets with its OWN buffer — never shares repair_batch_reuse
    /// with the recv-inline path (the two are mutually exclusive via
    /// repair_tile_active, but separate buffers make that structural).
    tile_repair_batch: ?packet.PacketBatch = null,

    const Self = @This();

    /// One parked zero-copy frame awaiting a free verify queue (Option A).
    pub const StagingEntry = struct {
        ref: af_xdp.UmemFrameRef,
        index: u32,
        is_last: bool,
        fm_ptr: usize,
    };
    pub const STAGING_CAP: u32 = 4096; // ~320ms of turbine cover (12.5k pps) > a 212ms stall

    /// [REPAIR-INFLIGHT] per-peer repair score (peer-scoring lite).
    /// @prov:tvu.repair-inflight — req_cnt counts nonce-tracked
    /// WindowIndex sends, res_cnt counts inflight-matched responses, so the
    /// two are directly comparable (HWI/Orphan traffic doesn't skew either).
    pub const PeerScore = struct {
        req_cnt: u32 = 0,
        res_cnt: u32 = 0,
        total_rtt_ns: u64 = 0,
    };
    /// peer_scores capacity, reserved once at init (testnet gossip is ~2-3k
    /// repair-capable peers; matches the 8192 all_peers sampling buffer).
    const PEER_SCORES_CAP: u32 = 8192;
    /// DEAD peer: asked >32 times, never answered. @prov:tvu.repair-inflight
    /// (simplified to a hard skip).
    const PEER_DEAD_MIN_REQS: u32 = 32;
    /// FAST peer preference bound: mean matched RTT under 80ms.
    /// @prov:tvu.repair-inflight
    const PEER_FAST_RTT_NS: u64 = 80 * std.time.ns_per_ms;
    /// Max expired inflight entries drained per repair cycle.
    const INFLIGHT_DRAIN_MAX: usize = 256;

    pub const Config = struct {
        /// TVU port (for receiving shreds) — must match core config & gossip advertisement
        tvu_port: u16 = 8003,

        /// TVU forward port
        tvu_fwd_port: u16 = 8004,

        /// Repair port
        repair_port: u16 = 8003,

        /// Packet batch size
        batch_size: usize = 512,

        /// Maximum slots to track for repair (raised from 100 for catch-up)
        // d27p (2026-05-11): bumped 100 → 5000. During catchup we typically
        // have 400-500 slots in progress (the catchup-seed range). Capping
        // at 100 with HashMap-bucket iteration order means the same ~100
        // slots get repair fills every iteration; the other 300-400 stay
        // at 1-2 shreds forever and never complete. Empirical: 280 slots
        // completed across the entire run but slots root+1..root+17
        // received only 2 inserts each (the seed-burst HighestWindowIndex
        // responses); their WindowIndex fill-in fan-out never reached
        // them. 5000 is well above the burst size and gives all in-progress
        // slots a fair shake.
        max_repair_slots: usize = 5000,

        /// Repair request interval (ms) — lowered from 100 for faster catch-up
        repair_interval_ms: u64 = 50, // Base interval; actual sleep is adaptive

        /// Enable AF_XDP acceleration (requires root/CAP_NET_RAW)
        /// Uses SKB mode + copy mode to avoid ixgbe driver lockups
        enable_af_xdp: bool = false, // FIXED: Must be explicitly enabled via --enable-af-xdp

        /// Enable io_uring acceleration (Linux 5.1+)
        enable_io_uring: bool = true,

        /// Enable AF_XDP zero-copy mode (requires mlx5/ice NIC driver)
        /// Controlled by --xdp-zero-copy CLI flag, default false for ixgbe safety
        xdp_zero_copy: bool = false,

        /// Enable FEC Reed-Solomon recovery (reconstructs missing shreds from parity)
        /// Default false (Data-Only mode) until RS stability is verified on testnet.
        /// Set to true via --enable-fec-recovery to activate erasure coding.
        enable_fec_recovery: bool = true,

        /// Enable SIMD-accelerated GF(2^8) for FEC (GFNI on Zen 4, AVX2 fallback)
        enable_simd_fec: bool = true,

        /// Network interface for AF_XDP (empty = auto-detect)
        interface: []const u8 = "",

        /// Bind repair socket to a specific IP (for dual-NIC setups)
        /// When set, repair traffic goes through the NIC with this IP.
        /// Example: "203.0.113.7" to use Broadcom NIC for repairs.
        repair_bind_addr: []const u8 = "",

        /// Network interface for AF_XDP repair socket (empty = same as interface)
        /// Example: "enp5s0f1np1" for Broadcom NIC repair AF_XDP
        repair_interface: []const u8 = "",

        /// Validator keypair (for signing repair requests)
        keypair: ?*const core.Keypair = null,

        /// Expected shred version (for filtering peers)
        shred_version: u16 = 0,

        /// Static leader for testing (bypasses LeaderSchedule)
        static_leader: ?core.Pubkey = null,
    };

    pub const Stats = struct {
        shreds_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        shreds_inserted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        shreds_duplicate: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        shreds_invalid: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        // 2026-06-13: shreds dropped at ZC ingest for wrong shred-version (the
        // AF_XDP phantom-slot root fix — garbage/misparsed frames carry a random
        // version field). @prov:tvu.shred-version-discard
        zc_version_rejects: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repairs_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repairs_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repairs_served: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repair_requests_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        slots_completed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        max_slot_seen: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repair_pings_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        unknown_repair_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repair_xdp_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repair_kernel_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        // Network-citizenship counters (2026-06-21). shreds_retransmitted: outbound
        // turbine retransmit packets sent to tree children (gated -Dturbine_retransmit +
        // VEX_TURBINE_RETRANSMIT). repairs_dropped_ratelimit: repair-serve responses
        // dropped by the token-bucket flood backstop (VEX_REPAIR_RATELIMIT_MBPS).
        shreds_retransmitted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        repairs_dropped_ratelimit: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        // 2026-07-07 (task #42 option (c), carrier 420258409 follow-up): NEW
        // frames shed at the recv→verify handoff because the UMEM recycle
        // reservoir was below VEX_UMEM_RESERVE ([RX-SHED]). This is proactive
        // backpressure, NOT a fault — every shed frame is released cleanly and
        // recovered exactly like a turbine/repair-recoverable network loss,
        // distinct from frame_overwrite_dropped (shred.zig), which counts
        // reactive drops of frames the NIC ALREADY recycled mid-processing.
        rx_shed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        // Diagnostic counters for debugging (permanent)
        packets_by_size: [1400]std.atomic.Value(u64) = .{std.atomic.Value(u64).init(0)} ** 1400,
        shred_types_seen: [256]std.atomic.Value(u64) = .{std.atomic.Value(u64).init(0)} ** 256,
        last_diagnostic_time: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !*Self {
        const service = try allocator.create(Self);
        service.* = .{
            .allocator = allocator,
            .shred_io = null,
            .repair_io = null,
            .xdp_manager = null,
            .shred_socket = null,
            .repair_socket = null,
            .tvu_port = config.tvu_port,
            .tvu_fwd_port = config.tvu_fwd_port,
            .repair_port = config.repair_port,
            .shred_assembler = if (config.enable_fec_recovery and config.enable_simd_fec)
                try shred_mod.ShredAssembler.initWithFecAndSimd(allocator, config.shred_version)
            else if (config.enable_fec_recovery)
                try shred_mod.ShredAssembler.initWithFecRecovery(allocator, config.shred_version)
            else
                try shred_mod.ShredAssembler.initWithShredVersion(allocator, config.shred_version),
            .ledger_db = null,
            .leader_cache = null,
            .gossip_service = null,
            .slot_sink = null,
            .repair_peers_override = .empty,
            .repair_peers_mutex = .{},
            .cluster_slots = cluster_slots_mod.ClusterSlots.init(allocator),
            .repair_tile_thread = null,
            .repair_tile_active = false,
            .running = std.atomic.Value(bool).init(false),
            .pending_slots = .empty,
            .pending_slots_mutex = .{},
            .stats = .{},
            .config = config,
            .using_accelerated_io = false,
            .turbine = Turbine.init(allocator),
            .turbine_retransmit_armed = (comptime build_options.turbine_retransmit) and
                (std.posix.getenv("VEX_TURBINE_RETRANSMIT") != null),
            .repair_bucket = RepairTokenBucket.initFromEnv(),
            .catchup_adaptive_refire = core.envFlagValueArmed(std.posix.getenv("VEX_CATCHUP_ADAPTIVE_REFIRE")),
            .repair_inflight_enabled = core.envFlagValueArmed(std.posix.getenv("VEX_REPAIR_INFLIGHT")),
            .last_repair_time_ns = 0,
            .last_turbine_update_ns = 0,
            .last_diag_ns = 0,
            .start_time_ns = @intCast(std.time.nanoTimestamp()),
            .repair_dedup = std.AutoHashMap(u128, u64).init(allocator),
            .last_dedup_cleanup_ns = 0,
            .identity = if (config.keypair) |kp| core.Pubkey{ .data = kp.public.data } else null,
            .thread_pool = undefined,
            .retransmit_stage = undefined,
            .umem_reserve = umemReserveFrames(),
        };

        // [REPAIR-INFLIGHT] (2026-07-06): allocate the fixed inflight pool +
        // reserve the peer-score capacity ONCE here — the repair hot path then
        // never allocates. All of it only when the gate is armed; unset ⇒ no
        // memory cost, inflight stays null and every gated branch is dead.
        if (service.repair_inflight_enabled) {
            const table = try allocator.create(repair_inflight.InflightTable);
            errdefer allocator.destroy(table);
            table.* = try repair_inflight.InflightTable.init(allocator);
            service.inflight = table;
            try service.peer_scores.ensureTotalCapacity(allocator, PEER_SCORES_CAP);
            if (std.posix.getenv("VEX_REPAIR_TIMEOUT_MS")) |v| {
                const ms = std.fmt.parseInt(u32, std.mem.trim(u8, v, " \t\r\n"), 10) catch 150;
                if (ms > 0) service.inflight_timeout_ns = @as(i64, ms) * std.time.ns_per_ms;
            }
            std.log.info("[REPAIR-INFLIGHT] armed: pool={d} timeout_ms={d} (FD fd_inflight port; VEX_REPAIR_INFLIGHT)", .{
                repair_inflight.POOL_CAP, @divTrunc(service.inflight_timeout_ns, std.time.ns_per_ms),
            });
        }

        // Initialize thread pool (4 threads for retransmission)
        try service.thread_pool.init(.{ .allocator = allocator, .n_jobs = 4 });

        // Initialize retransmit stage
        service.retransmit_stage = turbine_relay.TurbineRelay.init(allocator, &service.thread_pool);

        // Initialize Verify Tile (4 workers — repurposes idle thread capacity)
        service.verify_tile_instance = try verify_tile.VerifyTile.init(
            allocator,
            service.shred_assembler,
            service.leader_cache,
            config.static_leader,
            &service.stats,
            service.consensus_tracker,
            verify_tile.DEFAULT_NUM_WORKERS,
            // Option B (2026-06-14): allocate per-worker lock-free SPSC verify rings
            // only when AF_XDP zero-copy is configured. Kernel-UDP path keeps the
            // shared mutex ShredQueue, byte-identical to the proven behaviour.
            config.enable_af_xdp and config.xdp_zero_copy,
        );

        // Initialize Turbine tree with our identity if available
        if (service.identity) |id| {
            service.turbine.initTree(id) catch |err| {
                std.log.debug("[TVU init] turbine.initTree err: {any}\n", .{err});
            };
        }

        return service;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        if (self.verify_tile_instance) |vt| vt.deinit();
        // Cleanup thread pool
        self.thread_pool.deinit();

        // Cleanup accelerated I/O
        if (self.shred_io) |io| {
            io.deinit();
        }
        if (self.repair_io) |io| {
            io.deinit();
        }

        // Cleanup shared XDP manager (must be after sockets)
        if (self.xdp_manager) |mgr| {
            mgr.detach() catch |err| {
                std.log.debug("[TVU deinit] xdp_manager.detach err: {any}\n", .{err});
            };
            mgr.deinit();
        }

        // Cleanup legacy sockets
        if (self.shred_socket) |*sock| {
            sock.deinit();
        }
        if (self.repair_socket) |*sock| {
            sock.deinit();
        }

        if (self.skip_canon_produced) |p| self.allocator.free(p);
        // [REPAIR-INFLIGHT] free the gated inflight pool + peer scores (both
        // no-ops when the gate was never armed).
        if (self.inflight) |table| {
            table.deinit();
            self.allocator.destroy(table);
        }
        self.peer_scores.deinit(self.allocator);
        self.shred_assembler.deinit();
        self.allocator.destroy(self.shred_assembler);
        self.pending_slots.deinit(self.allocator);
        self.repair_peers_override.deinit(self.allocator);
        self.cluster_slots.deinit();
        self.repair_dedup.deinit();
        self.turbine.deinit();
        self.allocator.destroy(self);
    }

    /// Set external references
    pub fn setLedgerDb(self: *Self, db: *storage.LedgerDb) void {
        self.ledger_db = db;
    }

    pub fn setLeaderCache(self: *Self, cache: *consensus.leader_schedule.LeaderScheduleCache) void {
        self.leader_cache = cache;
    }

    pub fn setGossipService(self: *Self, gs: *gossip.GossipService) void {
        self.gossip_service = gs;
        // SLOT-AWARE REPAIR (2026-06-14): cross-link our ClusterSlots index into
        // gossip so EpochSlots (CrdsData tag 5) ingest feeds slot advertisers.
        // Null-guarded on the gossip side; before this call gossip just skips the
        // ingest (byte-identical to pre-change behaviour).
        gs.setClusterSlots(&self.cluster_slots);
        // DUPLICATE-SHRED (CRDS type 9): wire the FEC resolver so gossip can drain
        // detected equivocations and PUSH signed proofs. Detection ALWAYS runs in
        // the resolver (bank-hash-neutral); the outbound push stays gated by
        // -Dduplicate_shred + VEX_DUPLICATE_SHRED inside gossip. Safe always.
        gs.setDuplicateShredResolver(self.shred_assembler.getFecResolver());
        // Update Turbine tree when gossip service is set
        self.updateTurbineTree();
    }

    pub fn setSlotSink(self: *Self, sink: SlotSink) void {
        self.slot_sink = sink;
        sink.setShredAssembler(self.shred_assembler);
        // r49-B-rev-fix-2: VerifyTile path also needs to dispatch onSlotCompleted.
        if (self.verify_tile_instance) |vt| {
            vt.setTvuRef(self);
        }
        std.log.debug("[TVU] Replay stage connected (shred_assembler wired for r44 parent-bank lookup)\n", .{});
    }

    /// Wire the VexLedger persistent blockstore (flag-gated shadow-write). Called
    /// from main.zig only when built with -Dvex_ledger AND the VEX_LEDGER env is set.
    pub fn setVexLedger(self: *Self, vl: *vex_ledger_mod.VexLedger) void {
        self.vex_ledger = vl;
    }

    /// Wire the dedicated ledger tile. When set, completion ENQUEUES (non-blocking)
    /// instead of writing inline — fsync moves off the consensus threads.
    pub fn setLedgerTile(self: *Self, tile: *ledger_tile_mod.LedgerTile) void {
        self.ledger_tile = tile;
    }

    /// Create + spawn the ledger tile on `core_id` (a cold core) and wire it.
    /// `alloc` MUST be thread-safe (the tile's per-FINISH decode allocs on the
    /// consumer thread; init on main). Called from main.zig when VEX_LEDGER is set.
    pub fn startLedgerTile(self: *Self, alloc: std.mem.Allocator, vl: *vex_ledger_mod.VexLedger, core_id: u32) !void {
        const tile = try ledger_tile_mod.LedgerTile.init(alloc, vl, ledger_tile_mod.DEFAULT_CAPACITY);
        // Track 2c: wire the assembler so the cold consumer can backfill any
        // slot that sheds a dropped shred (see ledger_tile.zig's
        // backfillOneSuspect). Without this call the tile is still safe — it
        // degrades to the Track 2 stopgap (bigger ring, telemetry, no
        // guarantee) — but every production start should wire it.
        tile.setAssembler(self.shred_assembler);
        self.ledger_tile_thread = try tile.spawnPinned(core_id);
        self.ledger_tile = tile; // set LAST: producers only enqueue once the consumer is live
        std.log.warn("[LEDGER-TILE] spawned on cold core {d} (ledger I/O off the consensus hot path)", .{core_id});
    }

    /// Graceful shutdown (Q4): caller must QUIESCE the 4 completion producers FIRST,
    /// then call this — it stops the consumer and joins after the ring drains, so
    /// the last messages are fsync'd before exit.
    pub fn stopLedgerTile(self: *Self) void {
        if (self.ledger_tile) |tile| {
            self.ledger_tile = null; // stop new enqueues routing to the tile
            tile.stop();
            if (self.ledger_tile_thread) |t| t.join();
        }
    }

    /// r49-B-rev-fix-2: Dispatch a completed slot to replay stage. Used by both
    /// the repair path (processShred) and the VerifyTile worker after batch insert.
    /// Without this dispatch, slots assemble but never replay → 12.1% skip rate
    /// (per /tmp/vexor_skip_carrier_audit.md).
    /// r55-D: stale-repair-skip — drop completions for slots >50,000 behind the
    /// highest slot we've ever seen. Repair responses can flood the queue with
    /// truly deep-history slots (queue grew 0 → 900+ over 30 min in c9aeaa0
    /// pre-fix). r55-C tried 200 slots, but during normal catchup max_slot_seen
    /// can run hundreds of slots ahead of replay, which dropped legitimate
    /// turbine completions and stalled catchup at 62 slots/min. 50,000 only
    /// fires on TRULY deep-history floods (≈5h of slots) — never during normal
    /// catchup. At-tip behavior unaffected (max_seen ≈ slot, guard never fires).
    pub fn dispatchCompletedSlot(self: *Self, slot: u64) void {
        const STALE_REPAIR_SKIP_DEPTH: u64 = 50_000;
        const max_seen = self.stats.max_slot_seen.load(.monotonic);
        if (max_seen > STALE_REPAIR_SKIP_DEPTH and slot + STALE_REPAIR_SKIP_DEPTH < max_seen) {
            // Deep-history flood — keep the queue focused.
            return;
        }
        _ = self.stats.slots_completed.fetchAdd(1, .monotonic);

        // VexLedger shadow-write (flag-gated; comptime-dead by default). NEVER fatal.
        self.persistCompletedSlotIfEnabled(slot);

        self.pending_slots_mutex.lock();
        self.pending_slots.append(self.allocator, slot) catch |err| {
            std.log.debug("[TVU notifySlotCompleted] pending_slots.append err: {any}\n", .{err});
        };
        self.pending_slots_mutex.unlock();
        if (self.slot_sink) |rs| {
            // @prov:shred.assembled-boundaries — d27hh: use boundaries-aware
            // variant so replay can iterate per BlockComponent instead of scan-forward.
            if (self.shred_assembler.getAssembledDataWithBoundaries(slot)) |ar| {
                if (!rs.pushSlotForReplayWithBoundaries(slot, ar.data, ar.boundaries)) {
                    self.allocator.free(ar.data); // queue full — drop & free
                    if (ar.boundaries.len > 0) self.allocator.free(ar.boundaries);
                }
            } else |_| {}
        }
    }

    /// Flag-gated VexLedger persist of a just-completed slot. Comptime-dead by
    /// default; a no-op when vex_ledger isn't wired. MUST be called from EVERY
    /// slot-completion convergence point — the live completion paths do NOT all
    /// route through dispatchCompletedSlot: the VerifyTile path does (verify_tile.zig
    /// → dispatchCompletedSlot), but the kernel-UDP recv path and the repair/
    /// processShred path push to replay DIRECTLY. Tapping only dispatchCompletedSlot
    /// left vexledger.log empty on a real catch-up (Boot A, 2026-06-24). So this is
    /// invoked at all three: dispatchCompletedSlot + the two direct-push sites.
    fn persistCompletedSlotIfEnabled(self: *Self, slot: u64) void {
        if (comptime build_options.vex_ledger) {
            // Prefer the dedicated tile: ENQUEUE (non-blocking, ~ns) so the fsync
            // happens off this consensus-completion thread. Fall back to the inline
            // path only if the tile isn't wired (defensive — main.zig spawns it
            // whenever VEX_LEDGER is set).
            if (self.ledger_tile) |tile| {
                self.persistCompletedSlotViaTile(tile, slot);
            } else if (self.vex_ledger) |vl| {
                self.persistCompletedSlotToLedger(vl, slot);
            }
        }
    }

    /// Flag-gated shadow-write of a completed slot to VexLedger. NEVER fatal — a
    /// persistence error must never perturb replay/liveness (all fallible calls are
    /// `catch`-swallowed). Stores each present DATA shred verbatim + a SlotMeta
    /// derived from the shred set + headers. Only referenced under the comptime
    /// `build_options.vex_ledger` gate, so it is dead code in the default build.
    fn persistCompletedSlotToLedger(self: *Self, vl: *vex_ledger_mod.VexLedger, slot: u64) void {
        const raws = self.shred_assembler.getRawDataShredsForSlot(self.allocator, slot) catch return;
        defer {
            for (raws) |r| self.allocator.free(r.wire);
            self.allocator.free(raws);
        }
        if (raws.len == 0) return;

        // Store each data shred verbatim (raws is ascending, contiguous from 0).
        for (raws) |r| vl.putShred(slot, r.index, r.wire) catch {};

        // Derive SlotMeta. completed_data_indexes = indices whose data-shred flags
        // byte (offset 85) has DATA_COMPLETE (0x40). consumed = contiguous-from-0.
        var max_index: u32 = 0;
        var consumed: u32 = 0;
        var completed = std.ArrayListUnmanaged(u32){};
        defer completed.deinit(self.allocator);
        for (raws) |r| {
            if (r.index > max_index) max_index = r.index;
            if (r.index == consumed) consumed += 1;
            if (r.wire.len > 85 and (r.wire[85] & 0x40) != 0) {
                completed.append(self.allocator, r.index) catch {};
            }
        }
        // parent_slot from the first shred's parent_offset (wire[83..85] u16 LE).
        const first = raws[0].wire;
        const parent_slot: ?u64 = if (first.len >= 85) blk: {
            const po = std.mem.readInt(u16, first[83..][0..2], .little);
            break :blk if (po == 0) null else slot -| @as(u64, po);
        } else null;

        const meta = vex_ledger_mod.SlotMeta{
            .parent_slot = parent_slot,
            .received = max_index + 1,
            .consumed = consumed,
            .last_index = max_index,
            // PLACEHOLDER connected_flags (byte-FRAMING is exact; the CHAINED value
            // awaits the exact rc.1 ConnectedFlags algorithm — see CONNECTED-FLAGS-
            // SPEC.md). Final predicate (CONNECTED if parent-connected AND is_full,
            // PARENT_CONNECTED propagated to next_slots) lands in the consolidated
            // diff for LIVE's audit. Until then: 0 (unknown), never a wrong 0x02.
            .connected_flags = 0,
            .first_shred_timestamp = 0,
            .completed_data_indexes = completed.items,
        };
        vl.finishSlot(slot, meta) catch {};
    }

    /// Tile variant of persistCompletedSlotToLedger: identical shred set + SlotMeta
    /// derivation, but ENQUEUES to the ledger tile (non-blocking, drop-on-full)
    /// instead of writing inline. The tile drains + does putShred/finishSlot+fsync
    /// off this consensus-completion thread. A DELIBERATE MIRROR of the inline
    /// function above — keep the two derivations in lockstep. NEVER fatal.
    fn persistCompletedSlotViaTile(self: *Self, tile: *ledger_tile_mod.LedgerTile, slot: u64) void {
        const raws = self.shred_assembler.getRawDataShredsForSlot(self.allocator, slot) catch return;
        defer {
            for (raws) |r| self.allocator.free(r.wire);
            self.allocator.free(raws);
        }
        if (raws.len == 0) return;

        // ENQUEUE each data shred (copied into the ring; no ownership crosses).
        for (raws) |r| tile.enqueueShred(slot, r.index, r.wire);

        // Derive SlotMeta — identical to persistCompletedSlotToLedger.
        var max_index: u32 = 0;
        var consumed: u32 = 0;
        var completed = std.ArrayListUnmanaged(u32){};
        defer completed.deinit(self.allocator);
        for (raws) |r| {
            if (r.index > max_index) max_index = r.index;
            if (r.index == consumed) consumed += 1;
            if (r.wire.len > 85 and (r.wire[85] & 0x40) != 0) {
                completed.append(self.allocator, r.index) catch {};
            }
        }
        const first = raws[0].wire;
        const parent_slot: ?u64 = if (first.len >= 85) blk: {
            const po = std.mem.readInt(u16, first[83..][0..2], .little);
            break :blk if (po == 0) null else slot -| @as(u64, po);
        } else null;

        const meta = vex_ledger_mod.SlotMeta{
            .parent_slot = parent_slot,
            .received = max_index + 1,
            .consumed = consumed,
            .last_index = max_index,
            .connected_flags = 0,
            .first_shred_timestamp = 0,
            .completed_data_indexes = completed.items,
        };
        // FinishBlob.encode reads completed.items into the ring buf before the
        // `defer completed.deinit` frees it — safe (encode copies the values).
        tile.enqueueFinish(slot, meta);
    }

    pub fn setRepairPeersOverride(self: *Self, peers: []const RepairPeer) !void {
        self.repair_peers_override.clearRetainingCapacity();
        try self.repair_peers_override.appendSlice(self.allocator, peers);
    }

    /// Update Turbine tree from gossip peers
    /// Should be called periodically to keep tree fresh
    ///
    /// IMPORTANT: Only includes peers with matching shred_version.
    /// @prov:tvu.update-turbine-tree
    pub fn updateTurbineTree(self: *Self) void {
        const gs = self.gossip_service orelse return;

        // Collect gossip peers with matching shred version
        var peers = std.ArrayListUnmanaged(gossip.ContactInfo){};
        defer peers.deinit(self.allocator);

        const my_shred_version = self.config.shred_version;
        var filtered_count: usize = 0;
        var total_count: usize = 0;
        var no_tvu_count: usize = 0;
        var version_mismatch_count: usize = 0;

        gs.table.contacts_rw.lockShared();
        defer gs.table.contacts_rw.unlockShared();
        var iter = gs.table.contacts.iterator();
        while (iter.next()) |entry| {
            total_count += 1;
            const peer = entry.value_ptr.*;

            // Filter by shred version - only include matching peers
            // Shred version 0 means unknown/not set, accept those during bootstrap
            if (my_shred_version != 0 and peer.shred_version != 0 and
                peer.shred_version != my_shred_version)
            {
                filtered_count += 1;
                version_mismatch_count += 1;
                continue;
            }

            // Only include peers with valid TVU addresses
            if (peer.tvu_addr.port() == 0) {
                no_tvu_count += 1;
                continue;
            }

            peers.append(self.allocator, peer) catch continue;
        }

        std.log.debug("[TURBINE] updateTurbineTree: total_gossip_peers={d}, version_mismatch={d}, no_tvu={d}, valid_peers={d}, my_version={d}\n", .{ total_count, version_mismatch_count, no_tvu_count, peers.items.len, my_shred_version });

        // ── Stake map for the weighted-shuffle turbine tree ──────────────────
        // @prov:turbine.get-nodes-kat — TurbineTree.build() is a byte-faithful
        // port: [self] ++ gossip tvu_peers ++ ALL staked nodes,
        // each weighted by its REAL epoch stake, sorted desc(stake,pubkey). Its
        // ONLY defect was the INPUT here: a uniform stake=1000 over gossip-only
        // peers makes WeightedShuffle.first() pick a ~random, NON-CANONICAL root
        // (@prov:turbine.broadcast-peer) → the cluster's retransmit tree
        // never receives our shreds at the expected root → FEC sets never complete
        // cluster-side → our produced blocks are SKIPPED. (Diagnosed 2026-06-20;
        // see memory blockprod-turbine-uniform-stake-rootcause-2026-06-20.)
        //
        // REAL-STAKES path (gated, default OFF). Feeds the full epoch staked-node
        // set with real stakes from leader_cache.epoch_stakes (the SAME map the
        // stake-weighted REPAIR path uses, fillStakesForSlot). This tree ALSO feeds
        // retransmit (turbine_relay → getRetransmitChildren), so per RULE #13 the
        // default keeps the proven uniform baseline byte-identical; the real-stakes
        // path is enabled together with VEX_LEADER_BROADCAST (we only NEED the
        // canonical root when producing blocks). Auto-falls-back to uniform if the
        // epoch isn't populated yet (boot / pre-populateAgaveCanonical), with a loud
        // warning so a broadcast flip is never trusted on a non-canonical tree.
        const use_real_stakes = core.envFlagValueArmed(std.posix.getenv("VEX_TURBINE_REAL_STAKES"));

        var stakes = std.AutoHashMap([32]u8, u64).init(self.allocator);
        defer stakes.deinit();

        var real_n: usize = 0;
        if (use_real_stakes) {
            if (self.leader_cache) |lc| {
                // Slot whose epoch keys the stake lookup. Prefer the consensus
                // root bank's slot; before it is set (the first ~one tick after a
                // fresh-snapshot boot) fall back to catchup_root_slot (the boot
                // snapshot root) — same epoch, so copyEpochStakes (populated at
                // boot by populateAgaveCanonical, main.zig:698) returns the real
                // set from the FIRST tick instead of logging EMPTY → uniform-1000
                // for one cycle. Mirrors the root_slot/catchup_root_slot fallback
                // at ~tvu.zig:2798. Fully inside `use_real_stakes`, so the default
                // (env off) baseline is byte-identical; steady-state still uses
                // rb.slot exactly as before (root_bank is long-set by any epoch
                // boundary, so this never crosses into a wrong epoch).
                var stake_slot: u64 = self.catchup_root_slot;
                if (self.slot_sink) |rs| {
                    if (rs.rootBank()) |rb| stake_slot = rb.slot;
                }
                if (stake_slot != 0) real_n = lc.copyEpochStakes(stake_slot, &stakes);
            }
        }

        if (use_real_stakes and real_n > 0) {
            // Canonical: `stakes` is the full epoch staked-node set (real weights).
            // build() looks up each gossip peer's stake (0 if unstaked → weight-0,
            // invisible to first() per the zeros lemma) and adds every staked-but-
            // contactless node itself. @prov:turbine.get-nodes-kat — No
            // synthetic 1000; our own stake is already in the map iff we are staked.
            //
            // Logged at WARN (the live log is warn-only) so the real-stake tree is
            // VISIBLY confirmed — but rate-limited to the FIRST activation + every
            // ~10min (20 × 30s) so it doesn't spam. This is the precondition signal
            // for trusting produced-block acceptance at a leader window.
            const RsLog = struct {
                var n: u32 = 0;
            };
            const c = RsLog.n;
            RsLog.n += 1;
            if (c == 0 or c % 20 == 0) {
                std.log.warn("[TURBINE] canonical real-stake tree ACTIVE: {d} staked nodes (epoch of root slot){s}", .{ real_n, if (c == 0) " — FIRST activation, broadcast root now CANONICAL" else "" });
            }
        } else {
            if (use_real_stakes) {
                std.log.warn("[TURBINE] VEX_TURBINE_REAL_STAKES set but epoch_stakes EMPTY (real_n=0) — FALLING BACK to uniform-1000; broadcast root will be NON-canonical, do NOT trust produced-block acceptance until this clears", .{});
            }
            // LEGACY uniform-1000 baseline (default; or fallback when unpopulated).
            for (peers.items) |peer| {
                stakes.put(peer.pubkey.data, 1000) catch continue;
            }
            if (self.identity) |id| {
                stakes.put(id.data, 1000) catch |err| {
                    std.log.debug("[TVU buildTurbineTree] stakes.put err: {any}\n", .{err});
                };
            }
        }

        // Build the tree
        self.turbine.buildTree(peers.items, &stakes) catch |err| {
            std.log.debug("[TURBINE] Failed to build tree: {}\n", .{err});
            return;
        };

        const node_count = if (self.turbine.tree) |tree| tree.nodes.items.len else 0;
        std.log.debug("[TURBINE] Tree built with {d} nodes (shred_version={d}, real_stakes={any}, staked={d})\n", .{ node_count, my_shred_version, use_real_stakes and real_n > 0, real_n });
    }

    /// Start the TVU service
    pub fn start(self: *Self) !void {
        if (self.running.load(.seq_cst)) return;

        // ALWAYS create standard UDP sockets first — these are the RELIABLE path.
        // AcceleratedIO (AF_XDP/io_uring) has proven unreliable:
        //   - io_uring backend creates socket but never completes reads (0 workers)
        //   - AF_XDP BPF filter may miss ports
        // Standard UDP is the only path that reliably drains the kernel socket queue.
        std.log.debug("[TVU] Creating standard UDP sockets (ALWAYS)...\n", .{});
        std.log.info("[TVU] FEC Reed-Solomon recovery: {s}", .{
            if (self.config.enable_fec_recovery) "ENABLED" else "DISABLED (Data-Only mode)",
        });
        if (self.config.enable_simd_fec) {
            std.log.info("[TVU] SIMD FEC acceleration: ENABLED", .{});
        }
        {
            var repair_sock = socket.UdpSocket.init() catch |err| {
                std.log.debug("[TVU-ERROR] repair_socket.init() failed: {}\n", .{err});
                return err;
            };
            // If repair_bind_addr is set, bind to that specific IP (dual-NIC setup)
            // Otherwise bind to 0.0.0.0 (all interfaces).
            if (self.config.repair_bind_addr.len > 0) {
                // Parse IP address and bind to specific NIC
                var ip_parts: [4]u8 = .{ 0, 0, 0, 0 };
                var part_idx: usize = 0;
                var current: u16 = 0;
                for (self.config.repair_bind_addr) |ch| {
                    if (ch == '.') {
                        if (part_idx < 4) {
                            ip_parts[part_idx] = @intCast(current);
                            part_idx += 1;
                            current = 0;
                        }
                    } else if (ch >= '0' and ch <= '9') {
                        current = current * 10 + (ch - '0');
                    }
                }
                if (part_idx < 4) ip_parts[part_idx] = @intCast(current);

                const addr = std.net.Address.initIp4(ip_parts, self.repair_port);
                repair_sock.bind(addr) catch |err| {
                    std.log.debug("[TVU-ERROR] repair_socket.bind({s}:{d}) failed: {} — falling back to 0.0.0.0\n", .{ self.config.repair_bind_addr, self.repair_port, err });
                    repair_sock.bindPort(self.repair_port) catch |err2| {
                        std.log.debug("[TVU-ERROR] repair_socket fallback bindPort failed: {}\n", .{err2});
                        repair_sock.deinit();
                        return err2;
                    };
                };
                std.log.debug("[TVU] Repair socket bound to {s}:{d} (dual-NIC) ✓\n", .{ self.config.repair_bind_addr, self.repair_port });
            } else {
                repair_sock.bindPort(self.repair_port) catch |err| {
                    std.log.debug("[TVU-ERROR] repair_socket.bindPort({d}) failed: {}\n", .{ self.repair_port, err });
                    repair_sock.deinit();
                    return err;
                };
                std.log.debug("[TVU] Repair socket bound to port {d} ✓\n", .{self.repair_port});
            }
            self.repair_socket = repair_sock;
        }
        {
            var shred_sock = socket.UdpSocket.init() catch |err| {
                std.log.debug("[TVU-ERROR] shred_socket.init() failed: {}\n", .{err});
                return err;
            };
            shred_sock.bindPort(self.tvu_port) catch |err| {
                std.log.debug("[TVU-ERROR] shred_socket.bindPort({d}) failed: {}\n", .{ self.tvu_port, err });
                shred_sock.deinit();
                return err;
            };
            self.shred_socket = shred_sock;
            std.log.debug("[TVU] Shred socket bound to port {d} ✓\n", .{self.tvu_port});
        }

        self.using_accelerated_io = false;

        // ═══════════════════════════════════════════════════════════════
        // FIX #92 (Path A — multi-queue, as Firedancer does): Try SHARED XDP
        // first, which sets up AF_XDP zero-copy for BOTH shred (port 8003,
        // queue 0) AND repair (port 8002, queue 1). Uses pre-pinned BPF
        // program and maps at /sys/fs/bpf/vexor/{prog,xsks_map,port_filter}.
        //
        // Prerequisites: deploy.sh pins the program/maps at Step 5c, and
        // ntuple steers port 8002 → queue 1 (was queue 0; updated in same
        // commit). Without that ntuple change, repair packets would land on
        // queue 0's xsks_map slot which routes to shred_io — content-based
        // classifier in processPackets still handles them, but the queue
        // separation is preferred for clean per-tile metrics.
        //
        // If shared init fails (pinned objects missing, BPF refuses, etc),
        // we fall through to the standalone AF_XDP repair-only path below.
        // ═══════════════════════════════════════════════════════════════
        if (self.config.enable_af_xdp and self.config.xdp_zero_copy) {
            if (self.tryStartAcceleratedIO()) {
                self.using_accelerated_io = true;
                std.log.info("[TVU] ✅ FIX #92 — Shared XDP wired (TVU shreds + repair zero-copy)", .{});
            } else {
                std.log.warn("[TVU] FIX #92 — Shared XDP init failed; falling through to standalone repair-only AF_XDP", .{});
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // AF_XDP REPAIR PATH (legacy standalone): only entered if shared
        // XDP path above did not succeed. Creates a single AcceleratedIO
        // for the repair port with its OWN XDP program (single-port filter).
        // ═══════════════════════════════════════════════════════════════
        // #93 FIX (2026-05-29): legacy standalone repair-only AF_XDP path REMOVED.
        // Repair (8002) is ALWAYS served by the kernel repair_socket (the reliable
        // path). A repair XSK socket only ever caused the cross-port / dead-socket
        // bugs (Task #78, #93). If the shared shred-XSK path failed above, we run
        // fully on kernel-UDP (shred_socket + repair_socket), which is proven reliable.
        if (!self.using_accelerated_io and self.config.enable_af_xdp) {
            std.log.info("[TVU] Shared shred-XSK unavailable — shreds + repair on kernel UDP (reliable path)", .{});
            self.repair_io = null;
        }
        self.running.store(true, .seq_cst);

        std.log.debug(
            \\╔══════════════════════════════════════════════════════════╗
            \\║  TVU STARTED WITH STANDARD UDP                           ║
            \\║  Shred Port: {d}  Repair Port: {d}                       ║
            \\║  Repair ping/pong: ENABLED ✓                             ║
            \\╚══════════════════════════════════════════════════════════╝
            \\
        , .{ self.tvu_port, self.repair_port });

        // Set socket IO for retransmission
        if (self.shred_socket) |*sock| {
            self.retransmit_stage.setIoInterface(.{ .socket = sock });
        }

        // Start Verify Tile workers (must be after running = true)
        if (self.verify_tile_instance) |vt| {
            try vt.start();
            std.log.debug("[TVU] Verify Tile: {d} workers ACTIVE ✓\n", .{vt.num_workers});
        }
    }

    /// Try to start with accelerated I/O (AF_XDP with shared XDP program)
    fn tryStartAcceleratedIO(self: *Self) bool {
        // Auto-detect interface if not specified
        const interface = if (self.config.interface.len == 0) blk: {
            const detected = accelerated_io.detectDefaultInterface(self.allocator) catch {
                std.log.warn("[TVU] Failed to auto-detect network interface", .{});
                break :blk "eth0"; // Fallback
            };
            std.log.info("[TVU] Auto-detected interface: {s}", .{detected});
            break :blk detected;
        } else self.config.interface;

        // FIX #92: ports listed here MUST each have a corresponding XSK socket
        // registered in xsks_map. A port_filter entry without a matching socket
        // causes cross-port packet delivery — e.g. UDP/8004 traffic entering
        // queue 0 (no ntuple rule, default queue) would `bpf_redirect_map` into
        // the shred socket bound to that queue, which expects only 8003 frames.
        // When adding tvu_fwd_port (8004) here in the future, also register a
        // dedicated socket+queue for it and add the matching deploy.sh ntuple.
        // #93 FIX (2026-05-29): SINGLE-socket-on-q0. ONLY turbine shreds (8003) are
        // redirected to the XSK. Repair (8002) is REMOVED from this list so it is NOT
        // in the port_filter → repair packets XDP_PASS (xdp_filter.c:85) to the
        // ALWAYS-bound kernel repair_socket (created unconditionally at start(),
        // drained at ~:1220 — the "reliable path" per start()'s own comment).
        // WHY: with ntuple steering 8002→q0 (commit 3b34eff), an 8002 port_filter
        // entry makes the XDP prog bpf_redirect_map repair packets into the q0 SHRED
        // socket, whose parser (Shred.fromPayload) drops non-shreds → repair responses
        // silently lost → catchup stall (observed live 2026-05-29: root frozen,
        // gap widening). This is exactly the cross-port-delivery hazard the comment
        // above warns about. Turbine-only XSK + kernel-UDP repair = FD single-tile model.
        const validator_ports = [_]u16{
            self.tvu_port, // 8003 — turbine shreds (shred_io socket, queue 0) — ONLY XSK port
        };

        const xdp_mgr = shared_xdp.SharedXdpManager.init(
            self.allocator,
            interface,
            &validator_ports,
            // Driver mode is required for AF_XDP zero-copy on mlx5_core (the
            // Mellanox ConnectX-6 Dx is now permanent — see feedback_mellanox_permanent_HARD_RULE).
            // SKB mode is generic kernel-stack XDP and silently drops to copy mode,
            // which is why rx_xdp_redirect stayed at 0 in the vex-090 + 2026-05-02 retries.
            // The "SKB mode avoids ixgbe DMA lockups" rationale is obsolete Broadcom/Intel-era.
            .driver,
        ) catch |err| {
            std.log.warn("[TVU] Failed to create shared XDP manager: {}", .{err});
            // Fall back to per-socket accelerated I/O (non-shared)
            return self.tryStartAcceleratedIOFallback(interface);
        };
        errdefer xdp_mgr.deinit();

        // FIX #92: ATTACH program BEFORE creating XSK sockets. The kernel's
        // xsk_bind() requires an active XDP program on the interface — without
        // it, bind returns EINVAL. The previous order (sockets first, attach
        // last) was the canonical bug that left tryStartAcceleratedIO() unused.
        xdp_mgr.attach() catch |err| {
            std.log.warn("[TVU] Failed to attach shared XDP program: {}", .{err});
            xdp_mgr.deinit();
            return self.tryStartAcceleratedIOFallback(interface);
        };

        // Create shred socket with shared XDP
        const shred_io = accelerated_io.AcceleratedIO.init(self.allocator, .{
            .interface = interface,
            .bind_port = self.tvu_port,
            .queue_id = 0,
            .shared_xdp = xdp_mgr, // Pass shared manager
            .prefer_xdp = true,
            .umem_frame_count = UMEM_FRAME_COUNT_DEFAULT, // 2026-07-07: RE-GROWN 32K->131072 (task #42 rxshed-tune). RC7 (the actual "Sweeper head
            // corruption" mechanism, AFXDP-REWORK-PLAN-2026-06-11.md D4 - non-atomic MPMC free_ring race) was fixed
            // 2026-06-13 (commit 219fc32, free_mutex-serialized release()/replenishFillRing()) and has been live
            // ever since with no recurrence - the historical 05-28 revert blocker no longer applies. fill_size stays
            // the default 16384 (socket.zig:160, never overridden at any XdpSocket.init() call site) - unchanged,
            // so kernel Fill/RX ring sizing is byte-identical to today; only the software recycle reservoir grows.

            .zero_copy = self.config.xdp_zero_copy, // Controlled by --xdp-zero-copy flag (default: false for ixgbe safety)
        }) catch |err| {
            std.log.debug("[TVU] Failed to create shred socket: {}", .{err});
            xdp_mgr.deinit();
            return false;
        };
        errdefer shred_io.deinit();

        // Check if we actually got kernel bypass
        if (!shred_io.isKernelBypass()) {
            std.log.debug("[TVU] Shred socket didn't get kernel bypass", .{});
            shred_io.deinit();
            xdp_mgr.deinit();
            return self.tryStartAcceleratedIOFallback(interface);
        }

        // #93 FIX (2026-05-29): NO repair_io XSK socket. The 2nd socket on q1 only
        // ever got RSS-stray packets (ntuple sends 8002→q0, not q1) and was never
        // drained correctly (Task #78 dead-socket) — it was the FIX #92 mistake that
        // broke zero-copy delivery. Repair (8002) is NOT in validator_ports above, so
        // it falls through XDP_PASS to the always-bound kernel repair_socket.

        // FIX #92: program is attached above (pre-socket-creation). Assert the
        // invariant rather than re-calling attach() — keeps the success path
        // free of apologetic catch-blocks while crashing loudly if a future
        // refactor breaks the ordering contract.
        std.debug.assert(xdp_mgr.attached);

        self.shred_io = shred_io;
        self.repair_io = null; // single-socket-on-q0: turbine zero-copy, repair on kernel UDP
        self.xdp_manager = xdp_mgr;

        // Inject UMEM frame manager into ShredAssembler for zero-copy frame lifecycle
        if (shred_io.getXdpSocket()) |xdp| {
            if (xdp.getFrameManager()) |fm| {
                self.shred_assembler.setFrameManager(fm);
            }
        }

        std.log.info("[TVU] ✅ Shared XDP enabled for ports: {any}", .{validator_ports});
        return true;
    }

    /// Fallback accelerated I/O without shared XDP manager
    /// Accepts any backend better than standard UDP (AF_XDP or io_uring).
    fn tryStartAcceleratedIOFallback(self: *Self, interface: []const u8) bool {
        const shred_io = accelerated_io.AcceleratedIO.init(self.allocator, .{
            .interface = interface,
            .bind_port = self.tvu_port,
            .queue_id = 0,
            .prefer_xdp = self.config.enable_af_xdp,
            .prefer_io_uring = self.config.enable_io_uring,
            .umem_frame_count = UMEM_FRAME_COUNT_DEFAULT, // 2026-07-07: RE-GROWN 32K->131072 (task #42 rxshed-tune). RC7 (the actual "Sweeper head
            // corruption" mechanism, AFXDP-REWORK-PLAN-2026-06-11.md D4 - non-atomic MPMC free_ring race) was fixed
            // 2026-06-13 (commit 219fc32, free_mutex-serialized release()/replenishFillRing()) and has been live
            // ever since with no recurrence - the historical 05-28 revert blocker no longer applies. fill_size stays
            // the default 16384 (socket.zig:160, never overridden at any XdpSocket.init() call site) - unchanged,
            // so kernel Fill/RX ring sizing is byte-identical to today; only the software recycle reservoir grows.

            .zero_copy = self.config.xdp_zero_copy, // Controlled by --xdp-zero-copy flag
        }) catch |err| {
            std.log.debug("[TVU] Fallback shred socket init failed: {}", .{err});
            return false;
        };
        errdefer shred_io.deinit();

        // #93 FIX (2026-05-29): NO repair_io XSK socket (see tryStartAcceleratedIO).
        // Repair (8002) stays on the always-bound kernel repair_socket; only turbine
        // shreds (8003) go zero-copy on shred_io@q0.
        if (shred_io.getBackend() == .standard_udp) {
            std.log.warn("[TVU] Fallback accelerated I/O did not improve backend", .{});
            // CRITICAL: Must deinit to release bound ports! errdefer doesn't trigger on normal return
            shred_io.deinit();
            return false;
        }

        self.shred_io = shred_io;
        self.repair_io = null; // single-socket-on-q0: repair on kernel UDP
        self.xdp_manager = null;

        // Inject UMEM frame manager (fallback path may still have XDP)
        if (shred_io.getXdpSocket()) |xdp| {
            if (xdp.getFrameManager()) |fm| {
                self.shred_assembler.setFrameManager(fm);
            }
        }

        std.log.info("[TVU] ✅ Fallback accelerated I/O enabled (shred={s}, repair=kernel-UDP)", .{
            shred_io.getBackend().name(),
        });
        return true;
    }

    /// Stop the TVU service
    pub fn stop(self: *Self) void {
        self.running.store(false, .seq_cst);
        // Stop verify tile workers first (they hold assembler references)
        if (self.verify_tile_instance) |vt| vt.stop();
        // Join the receive thread to ensure it has exited before we free memory
        if (self.receive_thread) |thread| {
            thread.join();
            self.receive_thread = null;
        }
    }

    /// Process incoming shreds (alias for processPackets)
    pub fn processShreds(self: *Self) !void {
        _ = try self.processPackets();
    }

    /// Get the next completed slot, if any
    /// NOTE: Does NOT remove from assembler - caller must call clearCompletedSlot() after replay
    pub fn getCompletedSlot(self: *Self) ?core.Slot {
        self.pending_slots_mutex.lock();
        defer self.pending_slots_mutex.unlock();

        if (self.pending_slots.items.len == 0) return null;
        return self.pending_slots.orderedRemove(0);
    }

    /// Option A (2026-06-14): park a zero-copy frame whose verify-queue submit was
    /// `.contended` (a worker holds queue.mutex). Recv-thread-only. If staging is
    /// full, drop the OLDEST (release it) — overrun, turbine is repair-recoverable.
    fn stageFrame(self: *Self, ref: af_xdp.UmemFrameRef, index: u32, is_last: bool, fm_ptr: usize) void {
        if (self.staging_buf == null) {
            self.staging_buf = self.allocator.alloc(StagingEntry, STAGING_CAP) catch {
                const fm: *af_xdp.UmemFrameManager = @ptrFromInt(fm_ptr);
                fm.release(ref.frame_addr);
                self.staging_overrun += 1;
                return;
            };
        }
        const buf = self.staging_buf.?;
        if ((self.staging_head -% self.staging_tail) >= STAGING_CAP) {
            const old = buf[self.staging_tail % STAGING_CAP];
            const ofm: *af_xdp.UmemFrameManager = @ptrFromInt(old.fm_ptr);
            ofm.release(old.ref.frame_addr);
            self.staging_tail +%= 1;
            self.staging_overrun += 1;
        }
        buf[self.staging_head % STAGING_CAP] = .{ .ref = ref, .index = index, .is_last = is_last, .fm_ptr = fm_ptr };
        self.staging_head +%= 1;
        const d = self.staging_head -% self.staging_tail;
        if (d > self.staging_depth_max) self.staging_depth_max = d;
    }

    /// Option A: flush parked frames into the verify queue (tryLock-based, never
    /// blocks). Called each recv loop. Stops at the first .contended/.queue_full.
    fn drainStaging(self: *Self) void {
        const buf = self.staging_buf orelse return;
        const vt = self.verify_tile_instance orelse return;
        while (self.staging_tail != self.staging_head) {
            const e = buf[self.staging_tail % STAGING_CAP];
            switch (vt.submitZeroCopy(e.index, e.is_last, e.ref, e.fm_ptr)) {
                .submitted => self.staging_tail +%= 1,
                .contended, .queue_full => break,
            }
        }
    }

    /// Process incoming shred packets (call in main loop)
    pub fn processPackets(self: *Self) !ProcessResult {
        if (!self.running.load(.seq_cst)) return .{};

        var result = ProcessResult{};

        // Occupancy instrumentation (2026-06-13): timestamp the XSK-ingest phase
        // and the kernel repair-drain phase separately.
        const t_pp_start = std.time.nanoTimestamp();

        // Option A (2026-06-14): flush any frames parked from a prior contended
        // verify-queue submit FIRST, every loop (even idle loops), so the backlog
        // drains the instant the descheduled worker releases queue.mutex.
        self.drainStaging();

        // ═══════════════════════════════════════════════════════════════════
        // ZERO-COPY HOT PATH
        // Uses L2/L3/L4 header stripping to ingest raw hardware frames
        // directly into the verification pipeline via UMEM references.
        // ═══════════════════════════════════════════════════════════════════
        var used_zero_copy = false;

        if (self.shred_io) |io| {
            if (io.getXdpSocket()) |xdp| {
                // Attempt zero-copy receive directly from UMEM
                var frame_refs: [128]af_xdp.UmemFrameRef = undefined;
                const t_zc_recv0 = std.time.nanoTimestamp();
                const zc_count = xdp.recvZeroCopy(&frame_refs) catch |err| blk: {
                    if (err == error.FramePressure) {
                        // Safety valve triggered — too many frames held.
                        // Fall through to legacy copy path below.
                        std.log.warn("[TVU] FramePressure: spilling to copy path (held={d})", .{
                            if (xdp.getFrameManager()) |fm| fm.framesHeld() else 0,
                        });
                    }
                    break :blk @as(usize, 0);
                };
                result.zc_recv_only_ns = @intCast(std.time.nanoTimestamp() - t_zc_recv0);

                if (zc_count > 0) {
                    used_zero_copy = true;

                    // ── UMEM BACKPRESSURE GATE (2026-07-07, task #42 option (c)) ──
                    // ONE cheap atomic-load pair (freeDepth() = 2 atomic loads, no
                    // lock) per BATCH (not per frame) — this IS the "recv → ring
                    // submit to verify workers" decision point: if the recycle
                    // reservoir is already below the low-water mark, every frame in
                    // THIS batch is shed in Phase 1 below (released immediately,
                    // never parsed/verified/handed to a worker) rather than risking
                    // the NIC recycling one of them mid-flight ([FRAME-OVERWRITE]).
                    // A stale "not shedding" read for a few frames at the boundary
                    // is fine (the next batch re-checks); false-negatives here are
                    // strictly bounded by the reserve margin, not unbounded.
                    const shed_gate = if (xdp.getFrameManager()) |fm|
                        fm.shouldShed(self.umem_reserve)
                    else
                        false;

                    // ── Phase 1: Parse & validate WITHOUT lock (per-frame work) ──
                    const ValidFrame = struct {
                        slot: u64,
                        index: u32,
                        is_last: bool,
                        ref: af_xdp.UmemFrameRef,
                    };
                    var valid_frames: [128]ValidFrame = undefined;
                    var valid_count: usize = 0;

                    for (frame_refs[0..zc_count]) |*ref_ptr| {
                        const ref = ref_ptr.*;
                        result.shreds_processed += 1;

                        // Backpressure shed: STOP handing new frames to the verify
                        // pipeline while the pool is below reserve. Release back to
                        // the fill ring immediately (counted, rate-limited log) —
                        // never parse/verify a frame we're about to drop anyway.
                        // Same "check downstream capacity before accepting new work"
                        // shape. @prov:tvu.rx-shed-gate — checked every loop iter via
                        // cheap atomic seq-diffs, never
                        // a lock — see UmemFrameManager.shouldShed doc comment.
                        if (shed_gate) {
                            if (xdp.getFrameManager()) |fm| fm.release(ref.frame_addr);
                            const sc = self.stats.rx_shed.fetchAdd(1, .monotonic) + 1;
                            if (sc <= 5 or sc % 1000 == 0) {
                                std.log.warn("[RX-SHED] #{d} free_depth<{d} (UMEM recycle reservoir low) — new frame shed BEFORE verify-submit, not parsed", .{
                                    sc, self.umem_reserve,
                                });
                            }
                            continue;
                        }

                        // C2 (AFXDP-REWORK RC1): recvZeroCopy already stripped L2/L3/L4 →
                        // ref.data/ref.len IS the UDP payload (shred bytes) and ref.src_ip is
                        // set (socket.zig:838-862). The old re-parse here read shred bytes AS
                        // ethernet headers → garbage offset → Shred.fromPayload failed → ~100%
                        // of zero-copy shreds dropped. Use ref.data/ref.len directly.
                        if (ref.len == 0) {
                            if (xdp.getFrameManager()) |fm| fm.release(ref.frame_addr);
                            continue;
                        }

                        // Parse shred from UMEM frame data (no lock needed)
                        const shred = shred_mod.Shred.fromPayload(ref.data[0..ref.len]) catch {
                            if (xdp.getFrameManager()) |fm| fm.release(ref.frame_addr);
                            continue;
                        };

                        // ── ROOT FIX (2026-06-13): shred-VERSION filter at ZC ingest ──
                        // @prov:tvu.shred-version-discard — The
                        // AF_XDP zero-copy header-strip (parseHeaderOffset) returns
                        // payload_offset=0 on non-IPv4/UDP/malformed frames → the WHOLE
                        // ethernet frame is fed to fromPayload → the parsed `version`
                        // is garbage (header bytes) → without this filter it minted a
                        // phantom SlotAssembly (slot = garbage, far-future) that never
                        // completes → 154k in-progress slots → O(slots) repair work
                        // starves recvZeroCopy → RX ring overflow → turbine NIC-drop →
                        // catch-up collapse (trial-3). Real turbine shreds carry
                        // version == expected_shred_version. kernel-UDP never hit this
                        // (kernel strips headers + demuxes by port → only real shreds).
                        // Drop BEFORE FEC-add / verify-submit / assembler so no phantom
                        // state is created anywhere.
                        if (self.config.shred_version != 0 and shred.version() != self.config.shred_version) {
                            if (xdp.getFrameManager()) |fm| fm.release(ref.frame_addr);
                            const vr = self.stats.zc_version_rejects.fetchAdd(1, .monotonic) + 1;
                            if (vr <= 5 or vr % 5000 == 0) {
                                std.log.warn("[ZC-VERSION-REJECT] #{d} bogus_version={d} (expected {d}) parsed_slot={d} len={d} — misparsed/non-turbine frame dropped", .{
                                    vr, shred.version(), self.config.shred_version, shred.slot(), ref.len,
                                });
                            }
                            continue;
                        }

                        // ── Net-tile Stage 2 (2026-06-14): recv = RX + version-filter
                        //    + submit ONLY. The per-shred fec_resolver.addShred +
                        //    observeChainForShred that used to run HERE on the recv
                        //    thread (core 4) — for BOTH coding and data shreds — were
                        //    the residual recv-thread stall. They moved onto the 8
                        //    verify workers (ShredAssembler.insertFrameWithFec, called
                        //    from verify_tile.zig). CODING shreds are now ROUTED to the
                        //    ring like data shreds (they used to be FEC'd + dropped
                        //    here): RS recovery is ON by default, so the worker MUST
                        //    receive coding/parity shreds or recovery dies — and the
                        //    worker's fused insert handles `!isData` (FEC-only, never
                        //    into data-shred index space, Bug A). The worker re-parses
                        //    the frame, so the ValidFrame index/is_last carried here are
                        //    used only by the (vt==null) inline-fallback data path
                        //    below; for coding shreds they are vestigial. recv no
                        //    longer touches fec_resolver or the chain tracker at all.
                        if (valid_count < 128) {
                            valid_frames[valid_count] = .{
                                .slot = shred.slot(),
                                .index = shred.index(),
                                .is_last = shred.isLastInSlot(),
                                .ref = ref,
                            };
                            valid_count += 1;
                        } else {
                            // Overflow — release frame (shouldn't happen with 128-size buffers)
                            if (xdp.getFrameManager()) |fm| fm.release(ref.frame_addr);
                        }
                    }

                    // ── Phase 2: Verify & Batch Insert ──
                    if (valid_count > 0) {
                        for (valid_frames[0..valid_count]) |vf| {
                            if (self.verify_tile_instance) |vt| {
                                // Delegate verification to parallel workers. NON-BLOCKING and —
                                // critically — the recv thread NEVER HOLDS a frame waiting on the
                                // verify consumer. @prov:tvu.verify-nonblocking-handoff
                                // BOTH backpressure outcomes — queue full OR a worker holds the lock
                                // (.contended) — DROP the shred and RELEASE the frame immediately →
                                // it returns to the free ring → replenishFillRing keeps the FILL ring
                                // fed → no RX/fill starvation. Turbine/repair re-fetch the dropped
                                // shred; a bounded drop is far better than the unbounded fill-ring
                                // STARVATION that took AF_XDP delinquent under sustained tip load
                                // (rx_avail=1, fill_free=0, trylock_fail 24k). This REPLACES the
                                // Option-A staging, which HELD up to STAGING_CAP frames OUT of the
                                // fill ring during contention — the very cause of the starve.
                                // Option B (2026-06-14): when the per-worker lock-free
                                // SPSC rings are active, hand off via the round-robin
                                // ring producer — recv NEVER touches a mutex and NEVER
                                // drops on handoff unless ALL N rings are full (genuine
                                // overrun, counted in zc_overrun). Falls back to the
                                // tryLock+drop shared-queue path only if rings are absent.
                                const sr = if (vt.zc_rings != null)
                                    vt.submitZeroCopyRing(
                                        vf.index,
                                        vf.is_last,
                                        vf.ref,
                                        @intFromPtr(xdp.getFrameManager().?),
                                    )
                                else
                                    vt.submitZeroCopy(
                                        vf.index,
                                        vf.is_last,
                                        vf.ref,
                                        @intFromPtr(xdp.getFrameManager().?),
                                    );
                                switch (sr) {
                                    .submitted => {},
                                    .queue_full, .contended => xdp.getFrameManager().?.release(vf.ref.frame_addr),
                                }
                            } else {
                                // ── FALLBACK: INLINE VERIFICATION ──
                                // Testnet protection: If VerifyTile is off, we still MUST check sigs!
                                // NOTE: verify_tile_instance is initialized UNCONDITIONALLY at
                                // tvu.zig init (~line 383) so this branch is effectively dead in
                                // production; it is kept as a safety net. Net-tile Stage 2: it
                                // now routes through ShredAssembler.insertFrameWithFec so it does
                                // FEC (data AND coding), the recovered-shred pull, chain
                                // observation, and the Task #72 frame-release — identical to the
                                // worker path. Previously it did data-only assembly and relied on
                                // the recv-side addShred (now removed) for FEC; with coding shreds
                                // now routed into valid_frames, a bespoke data-only insert here
                                // would push coding bytes into data-shred index space (Bug A).
                                var leader_pubkey: ?core.Pubkey = if (self.leader_cache) |c| c.getSlotLeader(vf.slot) else null;
                                if (leader_pubkey == null) leader_pubkey = self.config.static_leader;

                                const parsed = shred_mod.parseShred(vf.ref.data[0..vf.ref.len]) catch {
                                    if (xdp.getFrameManager()) |fm| fm.release(vf.ref.frame_addr);
                                    continue; // Drop unparseable shred
                                };

                                if (leader_pubkey) |leader| {
                                    if (!parsed.verifySignature(&leader)) {
                                        if (xdp.getFrameManager()) |fm| fm.release(vf.ref.frame_addr);
                                        continue; // Drop invalid shred
                                    }
                                }

                                // FEC + chain + assembly + frame-release, all under one
                                // assembler.mutex window (releases the UMEM frame on every exit).
                                const ires = self.shred_assembler.insertFrameWithFec(parsed, vf.ref, 0) catch blk: {
                                    break :blk shred_mod.ShredAssembler.InsertResult.inserted;
                                };
                                if (ires == .completed_slot) {
                                    result.slots_completed += 1;
                                    _ = self.stats.slots_completed.fetchAdd(1, .monotonic);
                                    // VexLedger persist (flag-gated, never-fatal, idempotent) —
                                    // AF_XDP verify path. persist is last-wins per (slot,index) so a
                                    // double-persist with another path is harmless.
                                    self.persistCompletedSlotIfEnabled(vf.slot);
                                    self.pending_slots_mutex.lock();
                                    self.pending_slots.append(self.allocator, vf.slot) catch |err| {
                                        std.log.debug("[TVU verify-tile] pending_slots.append err: {any}\n", .{err});
                                    };
                                    self.pending_slots_mutex.unlock();
                                } else {
                                    _ = self.stats.shreds_inserted.fetchAdd(1, .monotonic);
                                }
                            }
                        }
                    }
                }
            }
        }
        // ═══════════════════════════════════════════════════════════════════
        // Used when: (1) no XDP, (2) FramePressure spill, (3) kernel socket
        //
        // CRITICAL: Drain socket in a LOOP (up to 8 passes) to prevent the
        // 55%+ UDP RcvbufErrors. A single recvmmsg returns at most batch_size
        // packets, but thousands can queue while we process the previous batch.
        // Sig solves this with a dedicated receiver thread; we drain aggressively.
        // ═══════════════════════════════════════════════════════════════════

        // ROOT FIX (2026-06-14): reuse a single PacketBatch (allocated once) instead
        // of alloc+free per pass — eliminates ~5 GB/s allocator churn that caused the
        // ~212ms recv stall.
        if (self.recv_batch == null) self.recv_batch = try packet.PacketBatch.init(self.allocator, self.config.batch_size);
        const batch = &self.recv_batch.?;
        var shred_pass: usize = 0;
        while (shred_pass < 32) : (shred_pass += 1) { // 32 passes to drain socket aggressively (was 8)
            batch.clear();

            // If zero-copy didn't fire (or partially consumed), also try legacy XDP copy path
            if (!used_zero_copy) {
                if (self.shred_io) |io| {
                    const xdp_packets = io.receiveBatch(self.config.batch_size) catch |err| {
                        std.log.debug("[TVU] AF_XDP receive error: {}", .{err});
                        break;
                    };

                    for (xdp_packets) |*xdp_pkt| {
                        if (batch.push()) |pkt| {
                            const copy_len = @min(xdp_pkt.len, pkt.data.len);
                            @memcpy(pkt.data[0..copy_len], xdp_pkt.payload()[0..copy_len]);
                            pkt.len = @intCast(copy_len);
                            pkt.src_addr = xdp_pkt.src_addr;
                            pkt.timestamp_ns = @intCast(xdp_pkt.timestamp);
                            pkt.flags = .{};
                        }
                    }
                }
            }
            // ALWAYS try kernel socket too — XDP may not be delivering packets
            // The kernel socket accumulates packets that XDP doesn't intercept
            if (self.shred_socket) |*sock| {
                _ = try sock.recvBatch(batch);
            }

            // If no packets this pass, socket is drained — stop
            const batch_slice = batch.slice();
            if (batch_slice.len == 0) break;

            // === FAST PATH: Minimal checking, push to verify tile ASAP ===
            // The verify workers do full parse + Ed25519 verify, so we only
            // need a size check here. This keeps the recv loop ultra-tight.
            for (batch_slice) |*pkt| {
                const payload = pkt.payload();
                if (payload.len >= 1000) {
                    // Looks like a shred (not a ping/request) — push to verify tile
                    if (self.verify_tile_instance) |vt| {
                        _ = vt.submit(payload);
                    } else {
                        // Fallback: no verify tile — use old inline path.
                        // r49-B-rev-fix: dispatch replay on .completed_slot, mirroring
                        // processShred()'s handling at lines 1213-1247. Without this,
                        // turbine-completed slots assemble but never replay → cap drift
                        // via skip rate (per r49-B-AUDIT verdict).
                        const shred_result = self.validateAndParseShred(pkt);
                        if (shred_result) |shred| {
                            if (self.shred_assembler.insert(shred)) |insert_res| {
                                if (insert_res == .completed_slot) {
                                    _ = self.stats.slots_completed.fetchAdd(1, .monotonic);
                                    // VexLedger persist (flag-gated, never-fatal) — this recv path
                                    // pushes to replay DIRECTLY (bypasses dispatchCompletedSlot).
                                    self.persistCompletedSlotIfEnabled(shred.slot());
                                    if (self.slot_sink) |rs| {
                                        if (self.shred_assembler.getAssembledDataWithBoundaries(shred.slot())) |ar| {
                                            if (!rs.pushSlotForReplayWithBoundaries(shred.slot(), ar.data, ar.boundaries)) {
                                                self.allocator.free(ar.data);
                                                if (ar.boundaries.len > 0) self.allocator.free(ar.boundaries);
                                            }
                                        } else |_| {}
                                    }
                                }
                            } else |_| {}
                        }
                    }
                    // Update stats (counter only, no parsing overhead)
                    _ = self.stats.shreds_received.fetchAdd(1, .monotonic);
                } else {
                    _ = self.stats.shreds_invalid.fetchAdd(1, .monotonic);
                }
                result.shreds_processed += 1;
            }
        }

        const t_recv_end = std.time.nanoTimestamp();
        result.recv_ns = @intCast(t_recv_end - t_pp_start);

        // Stage 2 (2026-06-17): the repair-packet DRAIN moved off recv core 4
        // onto the core-30 repair tile when active (completes the Stage-1 control
        // move so the recv loop no longer blocks up to ~700ms serving peer repair
        // requests). Runs inline here ONLY when the tile is not spawned
        // (kernel-UDP / AF_XDP-off) — byte-identical to before. SINGLE-CALLER by
        // construction: recv (here) XOR the tile, gated on repair_tile_active.
        if (!self.repair_tile_active) {
            const rr = self.drainRepairPackets(&self.repair_batch_reuse, 8);
            result.repairs_received += rr.responses;
            result.repair_requests_received += rr.requests;
        }

        result.repair_drain_ns = @intCast(std.time.nanoTimestamp() - t_recv_end);

        // ═══════════════════════════════════════════════════════════════════
        // STALE SLOT SWEEPER: Release leaked UMEM frames from dead slots.
        // Self-throttled to every 5 seconds — safe to call every iteration.
        // ═══════════════════════════════════════════════════════════════════
        _ = self.shred_assembler.sweepStaleSlots();

        return result;
    }

    const RepairDrainCounts = struct { responses: usize = 0, requests: usize = 0 };

    /// Stage 2 (2026-06-17): the repair-packet DRAIN, extracted verbatim from the
    /// old recv-inline block so it can run EITHER inline on recv (kernel-UDP
    /// fallback, repair_tile_active=false) OR on the dedicated core-30 repair tile
    /// (AF_XDP, repair_tile_active=true). This removes the up-to-~700ms recv-loop
    /// stall where core 4 served peer repair requests (ledger reads + sends)
    /// inline, blocking shred ingest and flapping the gap toward delinquency.
    ///
    /// SINGLE-CALLER by construction: repair_tile_active gates exactly one driver,
    /// and each caller passes its OWN reusable batch (recv: repair_batch_reuse;
    /// tile: tile_repair_batch) → no shared mutable batch state. Concurrency vs the
    /// verify workers (assembler insert via processShred) and replay (ledger reads
    /// in processRepairRequest) is UNCHANGED — these were already concurrent with
    /// those threads on the recv-inline path; we only relocate the caller off
    /// core 4. processShred remains single-caller-thread (this drain is its sole
    /// caller; see tvu.zig comment at processRepairResponse).
    fn drainRepairPackets(self: *Self, batch_slot: *?packet.PacketBatch, max_passes: usize) RepairDrainCounts {
        var counts = RepairDrainCounts{};
        if (batch_slot.* == null) {
            batch_slot.* = packet.PacketBatch.init(self.allocator, self.config.batch_size) catch return counts;
        }
        const repair_batch = &(batch_slot.*.?);
        var repair_pass: usize = 0;
        while (repair_pass < max_passes) : (repair_pass += 1) {
            repair_batch.clear();

            // Check AF_XDP accelerated I/O for repairs first (if enabled)
            if (self.repair_io) |io| {
                const xdp_packets = io.receiveBatch(self.config.batch_size) catch |err| {
                    std.log.debug("[TVU] AF_XDP repair receive error: {}", .{err});
                    break;
                };

                if (xdp_packets.len > 0) {
                    const xdp_total = self.stats.repair_xdp_packets.fetchAdd(xdp_packets.len, .monotonic);
                    if (@mod(xdp_total, 500) == 0) {
                        std.log.debug("[REPAIR-TRACE] AF_XDP delivered {d} packets (total={d})\n", .{ xdp_packets.len, xdp_total + xdp_packets.len });
                    }
                }

                for (xdp_packets) |*xdp_pkt| {
                    if (repair_batch.push()) |pkt| {
                        const copy_len = @min(xdp_pkt.len, pkt.data.len);
                        @memcpy(pkt.data[0..copy_len], xdp_pkt.payload()[0..copy_len]);
                        pkt.len = @intCast(copy_len);
                        pkt.src_addr = xdp_pkt.src_addr;
                        pkt.timestamp_ns = @intCast(xdp_pkt.timestamp);
                        pkt.flags = .{ .repair = true };
                    }
                }
            }
            // ALWAYS try kernel socket too — XDP may not be delivering repair packets
            const pre_kernel = repair_batch.slice().len;
            if (self.repair_socket) |*sock| {
                _ = sock.recvBatch(repair_batch) catch break;
            }
            const kernel_added = repair_batch.slice().len - pre_kernel;
            if (kernel_added > 0) {
                const kern_total = self.stats.repair_kernel_packets.fetchAdd(kernel_added, .monotonic);
                if (@mod(kern_total, 500) == 0) {
                    std.log.debug("[REPAIR-TRACE] Kernel socket delivered {d} packets (total={d})\n", .{ kernel_added, kern_total + kernel_added });
                }
            }

            // If we got no packets in this pass, stop draining
            if (repair_batch.slice().len == 0) break;

            for (repair_batch.slice()) |*pkt| {
                const packet_type = classifyRepairPacket(pkt);

                switch (packet_type) {
                    .repair_request => {
                        self.processRepairRequest(pkt) catch {};
                        counts.requests += 1;
                    },
                    .shred_response => {
                        self.processRepairResponse(pkt);
                        counts.responses += 1;
                    },
                    .repair_ping => {
                        // CRITICAL: Repair peers send Ping to verify us before sending shreds.
                        // We MUST respond with Pong to receive repair data!
                        self.handleRepairPing(pkt);
                        _ = self.stats.repair_pings_received.fetchAdd(1, .monotonic);
                    },
                    .unknown => {
                        // Unknown packet type - log occasionally
                        const count = self.stats.unknown_repair_packets.fetchAdd(1, .monotonic);
                        if (@mod(count, 1000) == 0) {
                            std.log.debug("[REPAIR] Unknown packet type (count={d}, len={d}, byte0=0x{x:0>2})\n", .{ count, pkt.len, pkt.data[0] });
                        }
                    },
                }
            }
        }
        return counts;
    }

    pub const ProcessResult = struct {
        shreds_processed: usize = 0,
        slots_completed: usize = 0,
        repairs_received: usize = 0,
        repair_requests_received: usize = 0,
        // Occupancy instrumentation (2026-06-13): per-phase nanoseconds within
        // processPackets so the run() summary can attribute loop time to XSK
        // ingest vs kernel repair-socket drain.
        recv_ns: u64 = 0, // whole ZC block (recvZeroCopy + parse/FEC/verify-submit)
        zc_recv_only_ns: u64 = 0, // recvZeroCopy() call ALONE (isolate 224ms: syscall/free_mutex vs downstream)
        repair_drain_ns: u64 = 0,
    };

    // ── Net-tile Stage 2 (2026-06-14): observeChainForShred REMOVED from here. ──
    // It used to run on the recv thread (core 4) at every FEC-complete during the
    // ZC ingest loop — part of the residual recv-thread stall. Its logic moved
    // verbatim into ShredAssembler.observeChain (shred.zig), invoked from
    // ShredAssembler.insertFrameWithFec on the 8 verify-worker threads, so FEC +
    // chain observation now happen off core 4. The chain tracker gained a
    // chain_mutex (slot_chain_tracker.zig) because it is no longer recv-exclusive.
    // The kernel-UDP path (insert/insertBatch) never observed the chain and is
    // unchanged — chain observation remains ZC-path-only.

    /// Process a single shred packet
    fn processShred(self: *Self, pkt: *const packet.Packet) ShredResult {
        const count = self.stats.shreds_received.fetchAdd(1, .monotonic);

        // Safety check: Discard packets that are obviously too short to be shreds
        // Standard Solana shreds are ~1200 bytes. Gossip pings (132) and Repair requests (160) are not shreds.
        if (pkt.payload().len < 1000) {
            _ = self.stats.shreds_invalid.fetchAdd(1, .monotonic);
            return .invalid;
        }

        // Report received milestone
        // Note: For efficiency in the hot path, we could sample this or only report once per slot
        // For now, tracker handles deduplication.
        // DEBUG: Log every shred's type byte and size
        // std.log.debug("[SHRED-DEBUG] byte[64]=0x{x:0>2} len={d}\n", .{ if (pkt.payload().len > 64) pkt.payload()[64] else 0, pkt.payload().len });
        // Track shred type at byte 64 for diagnostics (even if parsing fails)
        if (pkt.payload().len > 64) {
            const shred_type_byte = pkt.payload()[64];
            _ = self.stats.shred_types_seen[shred_type_byte].fetchAdd(1, .monotonic);
        }

        // Parse shred
        const shred = shred_mod.parseShred(pkt.payload()) catch |err| {
            _ = self.stats.shreds_invalid.fetchAdd(1, .monotonic);
            // DEBUG: Log why shred parsing failed (every 500th to limit spam)
            if (@mod(count, 50000) == 0) {
                std.log.debug("[SHRED-DIAG] Parse FAILED: {s} (count={d}, len={d}) type=0x{x:0>2}\n", .{ @errorName(err), count, pkt.payload().len, if (pkt.payload().len > 64) pkt.payload()[64] else 0 });
            }
            // FIX B1 (2026-06-14, AF_XDP catch-up wedge diagnostics — LOG ONLY):
            // a repair/catch-up shred that ARRIVES but fails to parse is otherwise
            // SILENT (the line above is .debug @every-50000th). During a wedge the
            // frontier slot can be stuck at have=N/need=N+1 with the missing
            // interior shred requested every cycle to hundreds of peers — if that
            // shred lands but fails to parse, we must SEE it. The shred slot is
            // unknown here (parse failed), so read it raw from payload()[65..73]
            // (canonical offset per shred.zig:80; len>=1000 is guaranteed by the
            // size guard above, so the read is in-bounds). Only warn for
            // catch-up/repair territory (slot < turbine_slot0) and only once per
            // second (time-based static throttle) so steady-state noise is ~zero.
            // Zero control-flow / validation change: we still `return .invalid`.
            {
                const t0_unset: u64 = std.math.maxInt(u64);
                const t0 = self.turbine_slot0.load(.acquire);
                const raw_slot: u64 = std.mem.readInt(u64, pkt.payload()[65..73], .little);
                if (t0 != t0_unset and raw_slot < t0) {
                    const ParseFailThrottle = struct {
                        var last_ns: i128 = 0;
                    };
                    const pf_now = std.time.nanoTimestamp();
                    if (pf_now - ParseFailThrottle.last_ns > std.time.ns_per_s) {
                        ParseFailThrottle.last_ns = pf_now;
                        std.log.warn("[REPAIR-PARSE-FAIL] slot={d} idx=? err={s} len={d} type=0x{x:0>2} (turbine_slot0={d})", .{
                            raw_slot,
                            @errorName(err),
                            pkt.payload().len,
                            if (pkt.payload().len > 64) pkt.payload()[64] else 0,
                            t0,
                        });
                    }
                }
            }
            return .invalid;
        };

        // DIAGNOSTIC: Log parsed shred details periodically
        if (@mod(count, 50000) == 0) {
            std.log.debug("[SHRED-DIAG] Parsed: slot={d} idx={d} is_data={} is_last={} ver={d} fec={d} len={d}\n", .{
                shred.slot(),    shred.index(),       shred.isData(),    shred.isLastInSlot(),
                shred.version(), shred.fecSetIndex(), pkt.payload().len,
            });
        }

        // Every 50K shreds: print variant byte histogram to diagnose coding shred reception
        if (@mod(count, 50000) == 0 and count > 0) {
            var data_total: u64 = 0;
            var code_total: u64 = 0;
            std.log.debug("[SHRED-TYPES] Variant byte histogram (after {d} shreds):\n", .{count});
            for (0..256) |i| {
                const type_count = self.stats.shred_types_seen[i].load(.monotonic);
                if (type_count > 0) {
                    const high = i & 0xF0;
                    const is_code = (high == 0x40 or high == 0x50 or high == 0x60 or high == 0x70);
                    const is_data = (high == 0x80 or high == 0x90 or high == 0xA0 or high == 0xB0);
                    const label: []const u8 = if (is_data) "DATA" else if (is_code) "CODE" else "OTHER";
                    std.log.debug("  0x{x:0>2}: {d} ({s})\n", .{ i, type_count, label });
                    if (is_data) data_total += type_count;
                    if (is_code) code_total += type_count;
                }
            }
            std.log.debug("[SHRED-TYPES] Total: DATA={d} CODE={d} ratio={d:.1}%\n", .{
                data_total,
                code_total,
                if (data_total + code_total > 0)
                    @as(f64, @floatFromInt(code_total)) * 100.0 / @as(f64, @floatFromInt(data_total + code_total))
                else
                    @as(f64, 0.0),
            });
        }

        // Track maximum slot seen from network shreds
        const shred_slot = shred.slot();

        // Sanity check: Solana slots won't reach 1 billion for many years.
        // This prevents corrupted packets from poisoning our max_slot_seen value.
        if (shred_slot < 1_000_000_000) {
            var current_max = self.stats.max_slot_seen.load(.monotonic);
            while (shred_slot > current_max) {
                const result = self.stats.max_slot_seen.cmpxchgWeak(current_max, shred_slot, .monotonic, .monotonic);
                if (result) |val| {
                    current_max = val;
                } else {
                    break; // Successfully updated
                }
            }
        }

        // Signature verification is now handled by the Verify Tile.
        // The shred is returned here and the raw payload is pushed to the
        // verify queue by the caller. Only verified shreds reach the assembler.

        // Insert into assembler
        // d27o-diag (2026-05-11): pre-compute "is this shred near root?"
        // so the per-result arms below can log selectively. Window = root..root+10.
        var near_root_off: u8 = 0; // 0 = not near root; 1..10 = root+N
        if (self.slot_sink) |rs| {
            if (rs.rootBank()) |rb| {
                if (shred_slot > rb.slot and shred_slot <= rb.slot + 10) {
                    near_root_off = @intCast(shred_slot - rb.slot);
                }
            }
        }

        // @prov:tvu.fec-boundary-discard — this is the
        // REPAIR-RESPONSE ingress path (processShred's sole caller is
        // processRepairResponse) — and the no-verify-tile fallback. Turbine
        // shreds are filtered in verify_tile.zig; this covers repair-fetched
        // shreds, which matters because repair is exactly how the true tail is
        // pulled after an off-boundary last is dropped. An off-boundary
        // LAST_IN_SLOT data shred is structurally non-canonical and is DISCARDED
        // outright — never into the FEC set/assembler. See verify_tile.zig.
        if (shred.isData() and shred.isLastInSlot() and
            (shred.index() + 1) % shred_mod.ShredAssembler.SlotAssembly.DATA_SHREDS_PER_FEC_BLOCK != 0)
        {
            if (@mod(count, 1000) == 0) {
                std.log.warn("[FEC-BOUNDARY-DISCARD] (fallback) slot={d} idx={d}: off-boundary LAST_IN_SLOT discarded (Agave/FD canonical)", .{ shred.slot(), shred.index() });
            }
            return .duplicate;
        }

        // ── SIMD-0337 discard_unexpected_data_complete_shreds (REPAIR path) ──
        // @prov:tvu.simd0337-discard — A DATA
        // shred carrying the DATA_COMPLETE flag (0x40) at an index other than
        // fec_set_index+31 is "unexpected". It is DISCARDED only once the
        // feature is EFFECTIVE for the shred's slot — and the feature is
        // effective one FULL EPOCH after activation (feature_epoch <
        // shred_epoch), NOT per-slot, so the gate does not fire during the
        // activation epoch (which would over-discard and fork). This BROADENS
        // the LAST_IN_SLOT discard above (0xC0) to mid-slot batch-complete
        // (0x40-alone) shreds. Default-keep on every
        // uncertain path: no root bank, feature absent / not yet epoch-
        // effective → fall through and insert. Coding shreds are exempt
        // (isUnexpectedDataComplete → false via its isData guard).
        if (shred_mod.isUnexpectedDataComplete(&shred)) {
            if (self.slot_sink) |rs| {
                if (rs.rootBank()) |rb| {
                    if (rb.discardUnexpectedDataCompleteEffective(shred.slot())) {
                        if (@mod(count, 1000) == 0) {
                            std.log.warn("[SIMD0337-DISCARD] (repair) slot={d} idx={d} fec_set={d}: unexpected DATA_COMPLETE discarded (Agave filter.rs:330; expected idx={d})", .{ shred.slot(), shred.index(), shred.fecSetIndex(), shred.fecSetIndex() + 31 });
                        }
                        return .duplicate;
                    }
                }
            }
        }

        const insert_result = self.shred_assembler.insert(shred) catch |err| {
            if (@mod(count, 50000) == 0) {
                std.log.debug("[SHRED-DIAG] Insert ERROR: {s} slot={d} idx={d}\n", .{ @errorName(err), shred.slot(), shred.index() });
            }
            return .error_inserting;
        };

        // DIAGNOSTIC: Log insert results periodically
        if (@mod(count, 50000) == 0) {
            const in_progress = self.shred_assembler.getInProgressSlotCount();
            const inserted_total = self.stats.shreds_inserted.load(.monotonic);
            const dup_total = self.stats.shreds_duplicate.load(.monotonic);
            std.log.debug("[SHRED-DIAG] Insert result={s} slot={d} idx={d} (inserted_total={d} dup_total={d} slots_tracking={d})\n", .{
                @tagName(insert_result), shred.slot(), shred.index(), inserted_total, dup_total, in_progress,
            });
        }

        switch (insert_result) {
            .inserted => {
                _ = self.stats.shreds_inserted.fetchAdd(1, .monotonic);
                if (near_root_off > 0) {
                    std.log.debug("[NEAR-ROOT-INSERT] slot=root+{d} idx={d} is_data={any} → inserted", .{ near_root_off, shred.index(), shred.isData() });
                }
                // d27k (2026-05-11): capture turbine_slot0 on the first turbine
                // shred ever inserted. Triggers the catchup-repair burst exactly
                // once. processShred handles only turbine-source shreds (repair
                // responses go through processRepairResponse / classifyRepairPacket
                // at tvu.zig:1428,1468), so this is the right capture point.
                const TURBINE_SLOT0_UNSET: u64 = std.math.maxInt(u64);
                // d27t (2026-05-11): only capture turbine_slot0 from a shred
                // that is meaningfully ABOVE catchup_root_slot. If bootstrap
                // performs incremental snapshot rotation, root_bank can jump
                // ~25K slots forward AFTER turbine starts receiving shreds.
                // A stale/out-of-order repair-response shred below root would
                // pin turbine_slot0 low, making seedCatchupRepairs's gap check
                // `turbine_slot0 <= root_slot + 1` perpetually true → seed-burst
                // is a no-op for the real catchup range (above root_bank).
                if (shred_slot > self.catchup_root_slot and
                    self.turbine_slot0.load(.acquire) == TURBINE_SLOT0_UNSET)
                {
                    if (self.turbine_slot0.cmpxchgStrong(TURBINE_SLOT0_UNSET, shred_slot, .seq_cst, .seq_cst) == null) {
                        // d27r: tell the assembler's stale-slot sweeper that
                        // everything below turbine_slot0 is repair-territory
                        // (5-min timeout), not live (30-s timeout). Without
                        // this, slots immediately above snapshot_root die
                        // before WindowIndex fill-in completes and the chain
                        // stalls at root forever.
                        self.shred_assembler.setCatchupCeiling(shred_slot);
                        // First-turbine-shred seed is also on the recv path → budget it.
                        self.seedCatchupRepairs(shred_slot, std.time.nanoTimestamp() + REPAIR_RECV_BUDGET_NS);
                    }
                }

                // ── TURBINE RETRANSMIT (gated, default OFF) ──────────────────────
                // Network-citizenship: re-transmit a successfully-inserted shred to
                // this node's turbine-tree children so we are not a leaf that forces
                // downstream peers to repair. Comptime-dead unless -Dturbine_retransmit
                // is built AND VEX_TURBINE_RETRANSMIT is set (turbine_retransmit_armed).
                // When the comptime flag is OFF this whole block is removed by the
                // compiler ⇒ the receive path is byte-identical to baseline.
                //
                // SCOPE / honest boundary: processShred's sole caller is
                // processRepairResponse (tvu.zig:~1972) plus the no-verify-tile
                // kernel-UDP fallback — so this v1 retransmits REPAIR-RESPONSE +
                // KERNEL-FALLBACK shreds, NOT the primary AF_XDP turbine flow (which
                // is assembled on the 8 verify-worker threads via insertFrameWithFec,
                // ~tvu.zig:1317, and never reaches here). Covering the verify-worker
                // flow is a documented follow-up (concurrent per-thread retransmit).
                //
                // DEDUP: this retransmit fires ONLY in the `.inserted` arm — the FIRST
                // successful assembler insert of a given shred. A second receipt of the
                // same shred returns `.duplicate` (not `.inserted`) and is NOT re-sent.
                // So the assembler insert already provides natural per-shred dedup: each
                // newly-inserted shred is retransmitted at most once. @prov:tvu.retransmit-dedup
                // A dedicated retransmit
                // LRU/bloom is optional defense-in-depth, not a correctness gap.
                if (comptime build_options.turbine_retransmit) {
                    if (self.turbine_retransmit_armed) {
                        self.retransmitShredToChildren(&shred, pkt.payload());
                    }
                }

                return .inserted;
            },
            .duplicate => {
                _ = self.stats.shreds_duplicate.fetchAdd(1, .monotonic);
                if (near_root_off > 0) {
                    std.log.debug("[NEAR-ROOT-DUP] slot=root+{d} idx={d} is_data={any}", .{ near_root_off, shred.index(), shred.isData() });
                }
                return .duplicate;
            },
            .completed_slot => {
                _ = self.stats.shreds_inserted.fetchAdd(1, .monotonic);
                const completed = self.stats.slots_completed.fetchAdd(1, .monotonic);
                std.log.warn("[SLOT-COMPLETED] slot={d} via idx={d} is_data={any} (total: {d})", .{ shred.slot(), shred.index(), shred.isData(), completed + 1 });
                // VexLedger persist (flag-gated, never-fatal) — processShred/repair path
                // pushes to replay DIRECTLY (bypasses dispatchCompletedSlot).
                self.persistCompletedSlotIfEnabled(shred.slot());
                if (near_root_off > 0) {
                    std.log.debug("[NEAR-ROOT-COMPLETED] slot=root+{d} idx={d} is_data={any}", .{ near_root_off, shred.index(), shred.isData() });
                }

                // Add to pending slots for replay
                self.pending_slots_mutex.lock();
                self.pending_slots.append(self.allocator, shred.slot()) catch |err| {
                    std.log.debug("[TVU processShred] pending_slots.append err: {any}\n", .{err});
                };
                self.pending_slots_mutex.unlock();

                // Feed completed slot to replay stage if connected
                if (self.slot_sink) |rs| {
                    // d27hh: use boundaries-aware variant
                    if (self.shred_assembler.getAssembledDataWithBoundaries(shred.slot())) |ar| {
                        if (!rs.pushSlotForReplayWithBoundaries(shred.slot(), ar.data, ar.boundaries)) {
                            self.allocator.free(ar.data);
                            if (ar.boundaries.len > 0) self.allocator.free(ar.boundaries);
                        }
                    } else |_| {}
                }

                return .completed_slot;
            },
            .dropped_frame_overwrite => {
                // FIX 2026-07-07: unreachable via THIS call site today —
                // ShredAssembler.insert() (the kernel-UDP/repair path this switch
                // is over) never produces this variant; only insertFrameWithFec's
                // zero-copy checksum-mismatch branch (~tvu.zig:1672, verify_tile.zig)
                // does. Handled defensively (not `unreachable`) so a future refactor
                // that shares more logic between insert()/insertFrameWithFec can't
                // silently turn a rare frame-drop into a panic on the repair path.
                std.log.warn("[SHRED-DIAG] unexpected dropped_frame_overwrite from repair-path insert() slot={d} idx={d}", .{ shred.slot(), shred.index() });
                return .duplicate;
            },
        }
    }

    /// turbine-retransmit (gated): send a successfully-inserted shred to this node's
    /// turbine-tree children. Resolves the shred's slot leader via leader_cache,
    /// computes the canonical child set (collectRetransmitTargetsForShred, under
    /// tree_mtx), and sends one copy of the ORIGINAL on-wire payload to each child's
    /// TVU addr via the shred socket. No-ops safely (sends nothing) if the leader is
    /// unknown, the tree is empty, or there is no socket. Never touches consensus.
    ///
    /// Only compiled when build_options.turbine_retransmit is true (the sole call site
    /// is itself `comptime`-gated), so the flag-off receive path is byte-identical.
    fn retransmitShredToChildren(self: *Self, shred: *const shred_mod.Shred, payload: []const u8) void {
        if (payload.len == 0 or payload.len > packet.MAX_PACKET_SIZE) return;

        // Resolve the shred's slot leader (the turbine-tree root). Without it we can't
        // pick the canonical child set, so no-op rather than send to a wrong set.
        const leader = if (self.leader_cache) |lc| (lc.getSlotLeader(shred.slot()) orelse return) else return;

        // ChaCha8 vs ChaCha20 must match the cluster's switch_to_chacha8_turbine
        // (SIMD-0332, ACTIVE on testnet) — same selector the broadcast path uses.
        const use_cha_cha_8 = std.posix.getenv("VEX_TURBINE_CHACHA20") == null;

        var targets = std.ArrayListUnmanaged(packet.SocketAddr){};
        defer targets.deinit(self.allocator);
        const n = self.turbine.collectRetransmitTargetsForShred(
            &targets,
            leader,
            shred.slot(),
            shred.index(),
            shred.isData(),
            use_cha_cha_8,
        );
        if (n == 0) return;

        // Send one copy of the original payload to each child via the shred socket.
        const sock = if (self.shred_socket) |*s| s else return;
        var sent: u64 = 0;
        for (targets.items) |addr| {
            var pkt = packet.Packet.init();
            @memcpy(pkt.data[0..payload.len], payload);
            pkt.len = @intCast(payload.len);
            pkt.src_addr = addr;
            if (sock.send(&pkt) catch null) |_| sent += 1;
        }
        if (sent > 0) {
            const total = self.stats.shreds_retransmitted.fetchAdd(sent, .monotonic);
            // Observability (2026-06-21): WARN-level so the arm is confirmable in the
            // default warn-only live log. One-time "ACTIVE" banner on the first
            // retransmit, then a coarse periodic heartbeat (~every 50k shreds) so the
            // running count is visible without a per-shred firehose. Per-shred detail
            // stays at debug.
            if (total == 0) {
                std.log.warn("[TURBINE-RETRANSMIT] ACTIVE — first shred retransmitted to {d} children (slot={d})", .{ sent, shred.slot() });
            } else if (@mod(total, 50000) < sent) {
                std.log.warn("[TURBINE-RETRANSMIT] heartbeat: total retransmitted={d} (slot={d} → {d} children)", .{ total + sent, shred.slot(), sent });
            }
            std.log.debug("[TURBINE-RETRANSMIT] slot={d} idx={d} → {d} children (total={d})", .{ shred.slot(), shred.index(), sent, total + sent });
        }
    }

    const ShredResult = enum {
        inserted,
        duplicate,
        invalid,
        completed_slot,
        error_inserting,
    };

    /// Validate and parse a packet into a Shred WITHOUT inserting into assembler.
    /// This performs all per-packet work (validation, diagnostics, signature check,
    /// max_slot tracking) but returns the parsed shred for batch insertion.
    /// Returns null if the packet is invalid or too short.
    fn validateAndParseShred(self: *Self, pkt: *const packet.Packet) ?shred_mod.Shred {
        const count = self.stats.shreds_received.fetchAdd(1, .monotonic);

        // Size check
        if (pkt.payload().len < 1000) {
            _ = self.stats.shreds_invalid.fetchAdd(1, .monotonic);
            return null;
        }

        // Track shred type byte for diagnostics
        if (pkt.payload().len > 64) {
            const shred_type_byte = pkt.payload()[64];
            _ = self.stats.shred_types_seen[shred_type_byte].fetchAdd(1, .monotonic);
        }

        // Parse shred
        const shred = shred_mod.parseShred(pkt.payload()) catch |err| {
            _ = self.stats.shreds_invalid.fetchAdd(1, .monotonic);
            if (@mod(count, 50000) == 0) {
                std.log.debug("[SHRED-DIAG] Parse FAILED: {s} (count={d}, len={d}) type=0x{x:0>2}\n", .{
                    @errorName(err),                                      count, pkt.payload().len,
                    if (pkt.payload().len > 64) pkt.payload()[64] else 0,
                });
            }
            return null;
        };

        // Periodic diagnostic
        if (@mod(count, 50000) == 0) {
            std.log.debug("[SHRED-DIAG] Parsed: slot={d} idx={d} is_data={} is_last={} ver={d} fec={d} len={d}\n", .{
                shred.slot(),    shred.index(),       shred.isData(),    shred.isLastInSlot(),
                shred.version(), shred.fecSetIndex(), pkt.payload().len,
            });
        }

        // Variant byte histogram every 50K shreds
        if (@mod(count, 50000) == 0 and count > 0) {
            var data_total: u64 = 0;
            var code_total: u64 = 0;
            std.log.debug("[SHRED-TYPES] Variant byte histogram (after {d} shreds):\n", .{count});
            for (0..256) |i| {
                const type_count = self.stats.shred_types_seen[i].load(.monotonic);
                if (type_count > 0) {
                    const high = i & 0xF0;
                    const is_code = (high == 0x40 or high == 0x50 or high == 0x60 or high == 0x70);
                    const is_data = (high == 0x80 or high == 0x90 or high == 0xA0 or high == 0xB0);
                    const label: []const u8 = if (is_data) "DATA" else if (is_code) "CODE" else "OTHER";
                    std.log.debug("  0x{x:0>2}: {d} ({s})\n", .{ i, type_count, label });
                    if (is_data) data_total += type_count;
                    if (is_code) code_total += type_count;
                }
            }
            std.log.debug("[SHRED-TYPES] Total: DATA={d} CODE={d} ratio={d:.1}%\n", .{
                data_total,
                code_total,
                if (data_total + code_total > 0)
                    @as(f64, @floatFromInt(code_total)) * 100.0 / @as(f64, @floatFromInt(data_total + code_total))
                else
                    @as(f64, 0.0),
            });
        }

        // Track max slot
        const shred_slot = shred.slot();
        if (shred_slot < 1_000_000_000) {
            var current_max = self.stats.max_slot_seen.load(.monotonic);
            while (shred_slot > current_max) {
                const cmpxchg_result = self.stats.max_slot_seen.cmpxchgWeak(current_max, shred_slot, .monotonic, .monotonic);
                if (cmpxchg_result) |val| {
                    current_max = val;
                } else {
                    break;
                }
            }
        }

        // Signature verification is handled by the Verify Tile.
        // No inline verification here — raw payload is pushed to the verify
        // queue by the caller, and workers do Ed25519 asynchronously.

        return shred;
    }

    /// Process repair response
    fn processRepairResponse(self: *Self, pkt: *const packet.Packet) void {
        const count = self.stats.repairs_received.fetchAdd(1, .monotonic);
        // d27k-diag: promote first-N + every-1000th to .warn so we can confirm
        // repair responses are actually flowing back from peers.
        if (count < 20 or @mod(count, 1000) == 0) {
            std.log.warn("[REPAIR-RESP] received #{d} (size={d})", .{ count, pkt.len });
        }

        // Repair responses contain: [shred payload] + [4-byte nonce]
        // The nonce is at the END, not the beginning
        const NONCE_SIZE: usize = 4;
        if (pkt.len > NONCE_SIZE + 83) { // Need at least 83 bytes for shred header + 4 byte nonce
            // Strip the nonce from the end
            var modified_pkt = pkt.*;
            const shred_len = pkt.len - NONCE_SIZE;
            // Just update the length - shred is already at the start
            modified_pkt.len = @intCast(shred_len);
            // FIX B2 (2026-06-14, AF_XDP catch-up wedge diagnostics — LOG ONLY):
            // if this repair-response shred is FOR the currently-tracked stuck
            // slot, count it so [REPAIR-STUCK] can report whether peers actually
            // ANSWER for that specific stuck slot. The shred slot is at the
            // canonical offset payload()[65..73] (shred.zig:80); shred_len > 83
            // (guard above) guarantees the read is in-bounds. Advisory counter
            // only — no validation / control-flow change; processShred runs
            // exactly as before.
            const tracked_stuck = self.stuck_slot.load(.acquire);
            if (tracked_stuck != 0 and shred_len >= 73) {
                const resp_slot = std.mem.readInt(u64, modified_pkt.data[65..73], .little);
                if (resp_slot == tracked_stuck) {
                    _ = self.stuck_slot_resp_count.fetchAdd(1, .monotonic);
                }
            }
            // [REPAIR-INFLIGHT] (2026-07-06, gated): match the response back to
            // its outstanding request. The trailing nonce (the 4 bytes stripped
            // above) + the shred header's slot (payload[65..73]) and index
            // (payload[73..77], shred.zig:80-81; shred_len > 83 guard above
            // keeps both reads in-bounds) form the FD match key
            // @prov:tvu.repair-inflight — nonce alone is insufficient, the
            // table verifies slot+idx. A match yields the RTT and credits the
            // asked peer's score. ADVISORY ONLY: whether or not it matches,
            // the shred proceeds through the unchanged verified ingest below.
            if (self.repair_inflight_enabled) {
                if (self.inflight) |table| {
                    const resp_nonce = std.mem.readInt(u32, pkt.data[shred_len..][0..4], .little);
                    const resp_slot = std.mem.readInt(u64, pkt.data[65..73], .little);
                    const resp_idx = std.mem.readInt(u32, pkt.data[73..77], .little);
                    const now_ns: i64 = @intCast(std.time.nanoTimestamp());
                    var peer_pk: [32]u8 = undefined;
                    if (table.remove(resp_nonce, resp_slot, resp_idx, now_ns, &peer_pk)) |rtt_ns| {
                        const rtt_pos: u64 = @intCast(@max(rtt_ns, 0));
                        self.inflight_fills_matched += 1;
                        self.inflight_rtt_sum_ns +|= rtt_pos;
                        self.inflight_rtt_cnt += 1;
                        if (self.peerScoreEntry(peer_pk)) |sc| {
                            sc.res_cnt +|= 1;
                            sc.total_rtt_ns +|= rtt_pos;
                        }
                    }
                }
            }
            _ = self.processShred(&modified_pkt);
        } else {
            // Packet too small, log and ignore
            if (@mod(count, 100) == 0) {
                std.log.debug("[REPAIR] Packet too small: {d} bytes (need > 87)\n", .{pkt.len});
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PACKET CLASSIFICATION. @prov:tvu.repair-packet-classify
    // ═══════════════════════════════════════════════════════════════════════════════

    const RepairPacketType = enum {
        repair_request, // Request for shreds (type 8-11)
        shred_response, // Valid shred data with proper header
        repair_ping, // RepairResponse::Ping — peer verifying us (MUST respond with pong!)
        unknown, // Unrecognized packet type
    };

    /// Classify packets received on repair socket
    /// @prov:tvu.repair-packet-classify
    ///   RepairProtocol enum: 0-6=Legacy, 7=Pong, 8=WindowIndex, 9=HighestWindowIndex, 10=Orphan, 11=AncestorHashes
    ///   RepairResponse enum: 0=Ping (sent BY peer BACK to us to verify we're real)
    ///   Actual shred data: raw shred bytes + 4-byte nonce appended
    fn classifyRepairPacket(pkt: *const packet.Packet) RepairPacketType {
        if (pkt.len < 4) return .unknown;

        const msg_type = std.mem.readInt(u32, pkt.data[0..4], .little);

        // Check 1: Is it a signed repair request from another validator? (types 8-11)
        if (msg_type >= 8 and msg_type <= 11) {
            return .repair_request;
        }

        // Check 2: RepairResponse::Ping — 132 bytes, type=0
        // Format: [type:4=0] [from_pubkey:32] [token:32] [signature:64] = 132 bytes
        // This is the most critical message type — without handling it, no repair data arrives!
        if (msg_type == 0 and pkt.len == 132) {
            return .repair_ping;
        }

        // Check 3: Is it a repair pong? (type 7) — just track it
        if (msg_type == 7 and pkt.len == 132) {
            return .repair_request; // Treat pongs as requests (we just ignore them)
        }

        // Check 4: Is it a valid shred response (raw shred bytes + 4-byte nonce)?
        // Shreds are typically 1200+ bytes. Check for valid shred variant byte at offset 64.
        if (pkt.len >= 200) {
            const shred_type = pkt.data[64];
            const is_valid_shred = switch (shred_type) {
                0x5A => true, // Legacy code shred
                0xA5 => true, // Legacy data shred
                0x40...0x59, 0x5B...0x7F => true, // Merkle code shreds (excluding 0x5A)
                0x80...0xA4, 0xA6...0xBF => true, // Merkle data shreds (excluding 0xA5)
                else => false,
            };
            if (is_valid_shred) {
                return .shred_response;
            }
        }

        // If none of the above, it's unknown
        return .unknown;
    }

    /// Handle a RepairResponse::Ping — generate and send a Pong back
    /// Without this, repair peers won't send us shred data!
    ///
    /// Ping format (bincode):  [type:4=0][from_pubkey:32][token:32][signature:64] = 132 bytes
    /// Pong format (bincode):  [type:4=7][from_pubkey:32][hash:32][signature:64] = 132 bytes
    ///   where hash = SHA256("SOLANA_PING_PONG" ++ token)
    ///   signature = Ed25519.sign(hash)
    fn handleRepairPing(self: *Self, pkt: *const packet.Packet) void {
        if (pkt.len != 132) return;

        const keypair = self.config.keypair orelse return;

        // Extract ping token from packet: bytes [36..68] = token (32 bytes)
        // Ping layout: [4 type][32 from_pubkey][32 token][64 signature]
        const token = pkt.data[36..68];

        // Compute pong hash: SHA256("SOLANA_PING_PONG" ++ token)
        const PING_PONG_PREFIX = [16]u8{
            'S', 'O', 'L', 'A', 'N', 'A', '_', 'P',
            'I', 'N', 'G', '_', 'P', 'O', 'N', 'G',
        };

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&PING_PONG_PREFIX);
        hasher.update(token);
        const hash = hasher.finalResult();

        // Sign the hash with our keypair
        const signature = keypair.sign(&hash);

        // Build pong packet:
        // [type:4=7][from_pubkey:32][hash:32][signature:64] = 132 bytes
        var pong_pkt = packet.Packet.init();
        std.mem.writeInt(u32, pong_pkt.data[0..4], 7, .little); // type = Pong
        @memcpy(pong_pkt.data[4..36], &keypair.public.data); // from = our pubkey
        @memcpy(pong_pkt.data[36..68], &hash); // hash
        @memcpy(pong_pkt.data[68..132], &signature.data); // signature
        pong_pkt.len = 132;
        pong_pkt.src_addr = pkt.src_addr; // send back to the ping sender

        // Send the pong
        // Send pong via kernel socket (AF_XDP TX requires L2/L3 framing)
        if (self.repair_socket) |*sock| {
            _ = sock.send(&pong_pkt) catch |err| {
                std.log.debug("[TVU pong-send] sock.send err: {any}\n", .{err});
            };
        }

        // Log occasionally
        const count = self.stats.repair_pings_received.load(.monotonic);
        if (@mod(count, 50) == 0) {
            std.log.debug("[REPAIR] Responded to ping #{d} with pong\n", .{count});
        }
    }

    /// Print comprehensive diagnostics every 30 seconds
    fn printComprehensiveDiagnostics(self: *Self) void {
        const s = &self.stats;

        std.log.debug("[DIAGNOSTICS] Shreds: R={d} I={d} Inv={d} Dup={d} | Repairs: Rec={d} Req={d} Pings={d} Unk={d} | Slots: C={d} Max={d}\n", .{
            s.shreds_received.load(.monotonic),
            s.shreds_inserted.load(.monotonic),
            s.shreds_invalid.load(.monotonic),
            s.shreds_duplicate.load(.monotonic),
            s.repairs_received.load(.monotonic),
            s.repair_requests_received.load(.monotonic),
            s.repair_pings_received.load(.monotonic),
            s.unknown_repair_packets.load(.monotonic),
            s.slots_completed.load(.monotonic),
            s.max_slot_seen.load(.monotonic),
        });

        // Alert on concerning patterns
        std.log.debug("[REPAIR-TRACE] XDP_pkts={d} Kernel_pkts={d}\n", .{
            s.repair_xdp_packets.load(.monotonic),
            s.repair_kernel_packets.load(.monotonic),
        });
        const unknown_count = s.unknown_repair_packets.load(.monotonic);
        const invalid_count = s.shreds_invalid.load(.monotonic);

        if (unknown_count > 1000) {
            std.log.debug("⚠️  WARNING: {d} unknown repair packets detected!\n", .{unknown_count});
        }
        if (invalid_count > 1000) {
            std.log.debug("⚠️  WARNING: {d} invalid shreds detected - possible protocol issue!\n", .{invalid_count});
        }

        // === COMPREHENSIVE NETWORK DIAGNOSTICS ===
        // Log repair peer availability from gossip
        if (self.gossip_service) |gs| {
            var total_peers: usize = 0;
            var repair_peers: usize = 0;
            var tvu_peers: usize = 0;
            gs.table.contacts_rw.lockShared();
            defer gs.table.contacts_rw.unlockShared();
            var iter = gs.table.contacts.iterator();
            while (iter.next()) |entry| {
                const info = entry.value_ptr;
                total_peers += 1;
                if (info.serve_repair_addr.port() > 0) repair_peers += 1;
                if (info.tvu_addr.port() > 0) tvu_peers += 1;
            }
            std.log.debug("[DIAGNOSTICS] Gossip peers: Total={d} TVU={d} Repair={d}\n", .{
                total_peers, tvu_peers, repair_peers,
            });
        } else {
            std.log.debug("[DIAGNOSTICS] Gossip service NOT CONNECTED!\n", .{});
        }

        // Log socket/IO status
        if (self.repair_socket == null and self.repair_io == null) {
            std.log.debug("[DIAGNOSTICS] WARNING: Repair socket AND IO are NULL!\n", .{});
        }
        if (self.shred_socket == null and self.shred_io == null) {
            std.log.debug("[DIAGNOSTICS] WARNING: Shred socket AND IO are NULL!\n", .{});
        }

        // Log shred type distribution (for debugging InvalidShredType)
        std.log.debug("[DIAGNOSTICS] Shred byte[64] distribution: ", .{});
        var found_types: usize = 0;
        for (0..256) |i| {
            const count = s.shred_types_seen[i].load(.monotonic);
            if (count > 0 and found_types < 10) {
                std.log.debug("0x{x:0>2}={d} ", .{ i, count });
                found_types += 1;
            }
        }
        std.log.debug("(showing top 10)\n", .{});
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // REPAIR REQUEST HANDLING - Serve shreds to other validators
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Check if packet is a repair request (vs response)
    fn isRepairRequest(pkt: *const packet.Packet) bool {
        if (pkt.len < 4) return false;
        const req_type = std.mem.readInt(u32, pkt.data[0..4], .little);
        return req_type >= 8 and req_type <= 11; // Types 8-11 are requests
    }

    /// Process incoming repair request
    fn processRepairRequest(self: *Self, pkt: *const packet.Packet) !void {
        if (pkt.len < 160) return; // Minimum Sig-compatible request size

        const request_type = std.mem.readInt(u32, pkt.data[0..4], .little);
        const recipient_pubkey = pkt.data[100..132];

        // Verify request is for us
        const our_pubkey = self.config.keypair.?.public.data;
        if (!std.mem.eql(u8, recipient_pubkey, &our_pubkey)) {
            return; // Not for us
        }

        const slot = std.mem.readInt(u64, pkt.data[144..152], .little);

        switch (request_type) {
            8 => { // WindowIndex
                const shred_idx = std.mem.readInt(u64, pkt.data[152..160], .little);
                try self.handleWindowIndexRequest(slot, @intCast(shred_idx), pkt.src_addr);
            },
            9 => try self.handleHighestWindowIndexRequest(slot, pkt.src_addr), // HighestWindowIndex
            10 => try self.handleOrphanRequest(slot, pkt.src_addr), // Orphan
            11 => try self.handleAncestorHashesRequest(slot, pkt.src_addr), // AncestorHashes
            else => std.log.debug("[Repair] Unknown request type: {d}", .{request_type}),
        }
    }

    /// Handle WindowIndex request - serve specific shred
    fn handleWindowIndexRequest(self: *Self, slot: u64, shred_idx: u32, from: packet.SocketAddr) !void {
        // 1. Try ShredAssembler first (fast path for recent slots)
        if (self.shred_assembler.getShred(slot, shred_idx) catch null) |shred| {
            defer shred.deinit(self.allocator);
            try self.sendRepairResponse(from, shred.rawData());
            _ = self.stats.repairs_served.fetchAdd(1, .monotonic);
            std.log.debug("[Repair] Served shred (assembler) slot={d} idx={d}", .{ slot, shred_idx });
            return;
        }

        // 2. Try LedgerDb (for older slots)
        if (self.ledger_db) |db| {
            if (db.getShred(slot, shred_idx)) |shred_data| {
                try self.sendRepairResponse(from, shred_data);
                _ = self.stats.repairs_served.fetchAdd(1, .monotonic);
                std.log.debug("[Repair] Served shred (ledger) slot={d} idx={d}", .{ slot, shred_idx });
                return;
            }
        }

        std.log.debug("[Repair] Shred not found slot={d} idx={d}", .{ slot, shred_idx });
    }

    /// Handle HighestWindowIndex request - serve slot boundary info
    fn handleHighestWindowIndexRequest(self: *Self, slot: u64, from: packet.SocketAddr) !void {
        var highest_idx: ?u32 = null;

        // Check ShredAssembler first
        highest_idx = self.shred_assembler.getHighestShredIndex(slot);

        // Check LedgerDb
        if (highest_idx == null) {
            if (self.ledger_db) |db| {
                if (db.getSlotMeta(slot)) |meta| {
                    highest_idx = meta.expected_shred_count;
                }
            }
        }

        if (highest_idx) |idx| {
            // Response format: [slot:8][highest_index:4]
            var buf: [12]u8 = undefined;
            std.mem.writeInt(u64, buf[0..8], slot, .little);
            std.mem.writeInt(u32, buf[8..12], idx, .little);
            try self.sendRepairResponse(from, &buf);
            std.log.debug("[Repair] Served highest index slot={d} idx={d}", .{ slot, idx });
        }
    }

    /// Handle Orphan request - serve parent slot's last shred
    fn handleOrphanRequest(self: *Self, slot: u64, from: packet.SocketAddr) !void {
        var parent_slot: ?u64 = null;
        var parent_shred_data: ?[]const u8 = null;

        // Find parent slot
        parent_slot = self.shred_assembler.getParentSlot(slot);
        if (parent_slot == null) {
            if (self.ledger_db) |db| {
                if (db.getSlotMeta(slot)) |meta| {
                    parent_slot = meta.parent_slot;
                }
            }
        }

        // Get last shred of parent
        if (parent_slot) |parent| {
            if (self.shred_assembler.getLastShred(parent)) |shred| {
                parent_shred_data = shred.rawData();
            }

            if (parent_shred_data == null) {
                if (self.ledger_db) |db| {
                    if (db.getSlotMeta(parent)) |meta| {
                        if (meta.expected_shred_count) |last| {
                            parent_shred_data = db.getShred(parent, last - 1);
                        }
                    }
                }
            }
        }

        if (parent_shred_data) |data| {
            try self.sendRepairResponse(from, data);
            std.log.debug("[Repair] Served orphan parent slot={d}", .{parent_slot.?});
        }
    }

    /// Handle AncestorHashes request - serve ancestor chain
    fn handleAncestorHashesRequest(self: *Self, slot: u64, from: packet.SocketAddr) !void {
        // Collect ancestors with their block hashes
        var ancestors = std.ArrayListUnmanaged(struct { slot: u64, hash: [32]u8 }){};
        defer ancestors.deinit(self.allocator);

        var current_slot: u64 = slot;
        var depth: usize = 0;
        const max_depth: usize = 100; // Limit chain length

        while (depth < max_depth) {
            var parent_slot: ?u64 = null;

            // Try to get hash from ledger
            if (self.ledger_db) |db| {
                if (db.getSlotMeta(current_slot)) |meta| {
                    if (meta.blockhash) |hash| {
                        try ancestors.append(self.allocator, .{ .slot = current_slot, .hash = hash.data });
                    } else {
                        break; // Can't continue without hash
                    }
                    parent_slot = meta.parent_slot;
                }
            }

            if (parent_slot) |parent| {
                current_slot = parent;
                depth += 1;
            } else {
                break; // Reached root
            }
        }

        // Send response
        if (ancestors.items.len > 0) {
            var buf: [4096]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            const writer = fbs.writer();

            // Format: [count:4][slot:8|hash:32]...
            try writer.writeInt(u32, @intCast(ancestors.items.len), .little);
            for (ancestors.items) |ancestor| {
                try writer.writeInt(u64, ancestor.slot, .little);
                try writer.writeAll(&ancestor.hash);
            }

            try self.sendRepairResponse(from, fbs.getWritten());
            std.log.debug("[Repair] Served {d} ancestors for slot={d}", .{ ancestors.items.len, slot });
        }
    }

    /// Send repair response packet
    fn sendRepairResponse(self: *Self, to: packet.SocketAddr, data: []const u8) !void {
        // For now, use standard UDP socket for repair responses
        // (accelerated I/O path would require PacketBuffer allocation)
        if (self.repair_socket) |*sock| {
            var pkt = packet.Packet.init();
            const len = @min(data.len, pkt.data.len);

            // Repair-serve flood backstop (defensive, default-active, generous). Debit
            // this response's wire size from the byte budget; if exhausted, DROP it
            // (a hostile peer can saturate at most `rate` B/s of our serve loop). The
            // ping/pong validation path does NOT go through here (handleRepairPing
            // sends pong directly via repair_socket), so peers can always validate us.
            // Liveness-only — never touches consensus / bank_hash.
            {
                const now = std.time.nanoTimestamp();
                self.repair_bucket_mutex.lock();
                const admit = self.repair_bucket.tryConsume(@intCast(len), now);
                self.repair_bucket_mutex.unlock();
                if (!admit) {
                    const dropped = self.stats.repairs_dropped_ratelimit.fetchAdd(1, .monotonic);
                    if (@mod(dropped, 256) == 0) {
                        std.log.debug("[REPAIR-RATELIMIT] dropped repair response ({d} bytes) — byte budget exhausted (total dropped={d}, rate={d} B/s)", .{ len, dropped + 1, self.repair_bucket.rate_bytes_per_sec });
                    }
                    return; // drop, do not serve
                }
            }

            @memcpy(pkt.data[0..len], data[0..len]);
            pkt.len = @intCast(len);
            pkt.src_addr = to;
            _ = try sock.send(&pkt);
        }
    }

    // C1 (2026-06-17): the dead `broadcastShred` (0 callers, superseded by broadcastProducedBlock)
    // was removed here. It routed via getRetransmitChildrenForShred → getRetransmitChildren, the
    // orphaned shuffle path that referenced the non-existent crypto.WeightedShuffle/ChaChaRng and
    // never compiled. The live leader path is broadcastProducedBlock → getBroadcastPeerForShred
    // (@prov:turbine.broadcast-peer, real weighted_shuffle.zig).

    /// leader_mode: shred a PRODUCED empty block (KAT-green block_broadcast) and broadcast each shred to
    /// its single turbine root (getBroadcastPeerForShred). Called from the replay thread via the
    /// produce-broadcast callback wired in main.zig. Liveness-only path — never touches consensus state.
    /// leader_mode (2026-06-19, multi-slot leader-window chaining): compute the produced block's
    /// last-FEC merkle root (= the NEXT slot's chained_root) WITHOUT transmitting. Wired to
    /// replay_stage.produce_blockid_fn so replay feeds the produced block_id forward as the produced
    /// slot's bank.block_id (enabling slots 2..N of our leader window to chain). Returns true + writes
    /// the root into `out` on success; false on shred-build failure (replay then leaves block_id null
    /// ⇒ next slot skips, as before). Same shredder + inputs as broadcastProducedBlock → identical root.
    pub fn computeProducedBlockId(
        self: *Self,
        entry_bytes: []const u8,
        slot: u64,
        parent_slot: u64,
        chained_root: [32]u8,
        secret: [64]u8,
        version: u16,
        out: *[32]u8,
    ) bool {
        const bb = @import("block_broadcast.zig");
        var block = bb.shredsFromEntryBytes(self.allocator, entry_bytes, slot, parent_slot, version, chained_root, secret) catch |e| {
            std.log.warn("[LEADER-PRODUCE] slot={d} block_id compute failed: {any}", .{ slot, e });
            return false;
        };
        defer block.deinit(self.allocator);
        out.* = block.block_id;
        return true;
    }

    pub fn broadcastProducedBlock(
        self: *Self,
        slot: u64,
        parent_slot: u64,
        entry_bytes: []const u8,
        chained_root: [32]u8,
        secret: [64]u8,
        version: u16,
    ) void {
        const bb = @import("block_broadcast.zig");
        // @prov:tvu.multi-fec-broadcast — shredsFromEntryBytes now splits a packed block into 1..N chained FEC sets.
        // We iterate EVERY set's 32 data + 32 code shreds. An empty/small block = one set.
        var block = bb.shredsFromEntryBytes(self.allocator, entry_bytes, slot, parent_slot, version, chained_root, secret) catch |e| {
            std.log.warn("[LEADER-BROADCAST] slot={d} shred build failed: {any}", .{ slot, e });
            return;
        };
        defer block.deinit(self.allocator);

        // C1 — CANONICAL stake-weighted single-root broadcast. @prov:turbine.broadcast-peer
        // For EACH shred we compute its one turbine root via the
        // stake-weighted shuffle seeded by (slot, on-wire index, type) and send exactly ONE
        // copy there — replacing the prior top-16 over-broadcast. The root re-propagates down
        // the turbine tree; a wrong-root shred is still accepted (liveness-only), so this is a
        // correctness/efficiency refinement, never a block-validity change.
        //
        // ROBUSTNESS NOTE (flagged for the broadcast-flip decision): @prov:turbine.broadcast-peer
        // is strictly one-copy-per-shred-to-root. That removes the over-broadcast redundancy the prior code
        // had. The 32 code (parity) shreds per FEC set already provide Reed-Solomon redundancy
        // (any 32 of 64 reconstruct the set), and each shred's root is independently chosen, so a
        // single slow/missing root does not lose the set. If the first live flip wants extra
        // first-hop redundancy it can be re-added behind a flag; the canonical default is 1 copy.
        //
        // use_cha_cha_8: switch_to_chacha8_turbine (SIMD-0332) is ACTIVE on testnet (epoch 909) and
        // mainnet, so the live default is ChaCha8. VEX_TURBINE_CHACHA20=1 forces the legacy ChaCha20
        // RNG for a pre-activation cluster (matches the cluster's active feature, never guessed).
        const use_cha_cha_8 = std.posix.getenv("VEX_TURBINE_CHACHA20") == null;

        // Telemetry: count datagrams actually handed to the kernel (sent) vs. dropped by a full
        // send buffer (WouldBlock = sendShredToPeer == false) vs. shreds with NO routable root
        // (tree empty / root lacks a TVU addr) SEPARATELY. A genuine (non-WouldBlock) send error
        // is skipped via `catch continue`.
        var sent: usize = 0;
        var dropped: usize = 0;
        var no_root: usize = 0;

        // Route+send a single on-wire shred to its canonical stake-weighted root.
        const Router = struct {
            fn send(svc: *Self, shred: []const u8, blk_slot: u64, use8: bool, s: *usize, d: *usize, nr: *usize) void {
                if (shred.len <= shred_header.VARIANT_OFF + 4) {
                    nr.* += 1;
                    return;
                }
                const variant = shred[shred_header.VARIANT_OFF];
                const is_data = shred_header.isData(variant);
                // on-wire index: u32 LE at offset 0x49 (== shred.index()).
                const index = std.mem.readInt(u32, shred[0x49..][0..4], .little);
                const addr = svc.turbine.getBroadcastPeerForShred(blk_slot, index, is_data, use8) orelse {
                    nr.* += 1;
                    return;
                };
                if (svc.sendShredToPeer(shred, addr) catch return) s.* += 1 else d.* += 1;
            }
        };

        for (block.sets) |set| {
            for (set.data) |dsh| Router.send(self, dsh, slot, use_cha_cha_8, &sent, &dropped, &no_root);
            for (set.code) |csh| Router.send(self, csh, slot, use_cha_cha_8, &sent, &dropped, &no_root);
        }
        if (sent == 0 and no_root > 0) {
            std.log.warn("[LEADER-BROADCAST] slot={d} NO turbine root for any shred (tree empty?) — block not broadcast", .{slot});
        }
        std.log.warn("[LEADER-BROADCAST] slot={d} parent={d} sent={d} dropped={d} no_root={d} chacha8={any} ({d} sets × 64 shreds, 1 copy/shred to canonical root)", .{ slot, parent_slot, sent, dropped, no_root, use_cha_cha_8, block.sets.len });
    }

    /// Send a shred to a specific peer over the kernel TVU UDP socket (port 8003).
    ///
    /// The shred bytes are the ENTIRE UDP payload (standard Solana TVU wire
    /// format); the source addr/port are irrelevant — peers authenticate by the
    /// leader's ed25519 signature in the shred, not by the sender's address.
    ///
    /// Returns true if the datagram was handed to the kernel, false if the send
    /// would block (WouldBlock = a DROPPED packet, NOT an error). A genuine send
    /// error propagates to the caller.
    ///
    /// NOTE: the old AF_XDP / shred_io TX branch was REMOVED. AcceleratedIO's
    /// sendBatch (accelerated_io.zig) writes raw bytes with NO IP/UDP framing and
    /// ignores the destination (`_ = dst_addr;`), so it could never deliver a
    /// shred to a peer. Kernel UDP via shred_socket is the only working TX path.
    fn sendShredToPeer(self: *Self, shred_data: []const u8, to: packet.SocketAddr) !bool {
        if (self.shred_socket) |*sock| {
            var pkt = packet.Packet.init();
            const len = @min(shred_data.len, pkt.data.len);
            @memcpy(pkt.data[0..len], shred_data[0..len]);
            pkt.len = @intCast(len);
            // UdpSocket.send() routes the datagram to pkt.src_addr (see
            // socket.zig packetAddrToSockaddr); for a SEND, src_addr carries the
            // DESTINATION. Returns false on WouldBlock.
            pkt.src_addr = to;
            return try sock.send(&pkt);
        }
        // No kernel TVU socket bound (should not happen post-start) — treat as a
        // drop rather than an error so the broadcast loop keeps going.
        return false;
    }

    /// Request repairs for missing shreds
    /// Request repairs using Sig-compatible signed format
    /// Format: [type:4][signature:64][sender:32][recipient:32][timestamp:8][nonce:4][slot:8][shred_idx:8] = 160 bytes
    /// Signature covers: bytes[0..4] + bytes[68..160] (type + everything after signature)
    ///
    /// Repair dedup timeout in nanoseconds.
    /// Each (slot, shred_idx) pair will only be re-requested once per this interval.
    /// 2 seconds gives peers time to respond before we retry with a different peer.
    const REPAIR_DEDUP_TIMEOUT_NS: u64 = 200 * std.time.ns_per_ms; // Base timeout (200ms for normal slots)

    /// Max entries before forced dedup cache cleanup
    const REPAIR_DEDUP_MAX_ENTRIES: usize = 50_000;

    /// Check if we should send a repair request for this (slot, idx) pair.
    /// Returns true if the request should be sent (not deduped).
    /// @prov:tvu.repair-dedup
    fn shouldRequestRepair(self: *Self, slot: u64, idx: u32) bool {
        // d27k (2026-05-11): bypass the 200ms throttle for slots in the
        // catchup gap `(snapshot_root, turbine_slot0]`. These are not
        // duplicates of in-flight turbine work; they're pure gap fills
        // that need to land as fast as repair peers can answer.
        // @prov:tvu.repair-dedup
        const turbine_slot0 = self.turbine_slot0.load(.acquire);
        const TURBINE_SLOT0_UNSET: u64 = std.math.maxInt(u64);
        const is_catchup_slot = turbine_slot0 != TURBINE_SLOT0_UNSET and slot < turbine_slot0;

        const key: u128 = (@as(u128, slot) << 32) | @as(u128, idx);
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());

        if (!is_catchup_slot) {
            if (self.repair_dedup.get(key)) |last_ts| {
                if (now_ns < last_ts + REPAIR_DEDUP_TIMEOUT_NS) {
                    return false; // Too soon, skip (deduped)
                }
            }
        }
        // Record this request timestamp regardless — we still want eventual
        // dedup hygiene if a catchup-range slot turns into a live slot
        // (which shouldn't happen, but is the safe behavior).
        self.repair_dedup.put(key, now_ns) catch |err| {
            std.log.debug("[TVU repair-dedup] put err: {any}\n", .{err});
        };
        return true;
    }

    /// Prune old entries from the dedup cache to prevent unbounded memory growth.
    /// Removes entries older than 2x the dedup timeout.
    fn pruneRepairDedup(self: *Self) void {
        const now_ns: u64 = @intCast(std.time.nanoTimestamp());
        const expiry = 2 * REPAIR_DEDUP_TIMEOUT_NS;

        // Collect keys to remove (can't modify during iteration)
        var keys_to_remove = std.ArrayListUnmanaged(u128){};
        defer keys_to_remove.deinit(self.allocator);

        var it = self.repair_dedup.iterator();
        while (it.next()) |entry| {
            if (now_ns > entry.value_ptr.* + expiry) {
                keys_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            _ = self.repair_dedup.remove(key);
        }

        if (keys_to_remove.items.len > 0) {
            std.log.debug("[REPAIR-DEDUP] Pruned {d} stale entries, {d} remaining\n", .{
                keys_to_remove.items.len, self.repair_dedup.count(),
            });
        }
    }

    // ── [REPAIR-INFLIGHT] helpers (all gated — no caller reaches these unless
    // VEX_REPAIR_INFLIGHT armed the lever at init) ────────────────────────────

    /// Next per-request nonce from the tile-owned monotonic counter.
    /// @prov:tvu.repair-inflight — wrap is safe — the
    /// table drops a stale same-nonce entry and remove() verifies slot+idx.
    fn nextInflightNonce(self: *Self) u32 {
        self.inflight_nonce +%= 1;
        return self.inflight_nonce;
    }

    /// Get-or-create a peer's score slot. Capacity was reserved at init so
    /// this NEVER allocates; once PEER_SCORES_CAP distinct peers are tracked,
    /// additional unseen peers go unscored (fail-open — they are simply
    /// neither preferred nor skipped).
    fn peerScoreEntry(self: *Self, pk: [32]u8) ?*PeerScore {
        if (self.peer_scores.getPtr(pk)) |p| return p;
        if (self.peer_scores.count() >= PEER_SCORES_CAP) return null;
        const gop = self.peer_scores.getOrPutAssumeCapacity(pk);
        gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    /// DEAD peer: asked >32 times, answered never. @prov:tvu.repair-inflight
    /// Unscored peers are NOT dead (fail-open).
    fn peerScoreDead(self: *Self, pk: [32]u8) bool {
        const sc = self.peer_scores.get(pk) orelse return false;
        return sc.req_cnt > PEER_DEAD_MIN_REQS and sc.res_cnt == 0;
    }

    /// FAST peer: has matched responses and mean RTT < 80ms.
    /// @prov:tvu.repair-inflight
    fn peerScoreFast(self: *Self, pk: [32]u8) bool {
        const sc = self.peer_scores.get(pk) orelse return false;
        if (sc.res_cnt == 0) return false;
        return (sc.total_rtt_ns / sc.res_cnt) < PEER_FAST_RTT_NS;
    }

    /// [REPAIR-INFLIGHT] send ONE signed type-8 WindowIndex request to ONE
    /// explicit peer with an explicit nonce — the timeout re-request path.
    /// Wire bytes are IDENTICAL to requestRepairs' builder. @prov:tvu.window-index-wire
    /// [type:4][sig:64][sender:32][recipient:32][ts:8][nonce:4]
    /// [slot:8][shred_idx:8] = 160 bytes, sign domain [0..4]+[68..160].
    /// Returns true only when the datagram actually left the socket.
    fn sendWindowIndexTo(self: *Self, keypair: *const core.Keypair, peer: RepairPeer, slot: u64, shred_idx: u32, nonce: u32) bool {
        const timestamp_ms: u64 = @intCast(std.time.milliTimestamp());
        var pkt = packet.Packet.init();
        // Message type: 8 = REPAIR_WINDOW_INDEX (4 bytes LE)
        std.mem.writeInt(u32, pkt.data[0..4], 8, .little);
        // Sender pubkey (bytes 68-99)
        @memcpy(pkt.data[68..100], &keypair.public.data);
        // Recipient pubkey (bytes 100-131)
        @memcpy(pkt.data[100..132], &peer.pubkey);
        // Timestamp in ms (bytes 132-139)
        std.mem.writeInt(u64, pkt.data[132..140], timestamp_ms, .little);
        // Nonce (bytes 140-143)
        std.mem.writeInt(u32, pkt.data[140..144], nonce, .little);
        // Slot (bytes 144-151)
        std.mem.writeInt(u64, pkt.data[144..152], slot, .little);
        // Shred index (bytes 152-159)
        std.mem.writeInt(u64, pkt.data[152..160], @as(u64, shred_idx), .little);

        // Sign bytes[0..4] + bytes[68..160] (type + everything after signature)
        var sign_buf: [96]u8 = undefined;
        @memcpy(sign_buf[0..4], pkt.data[0..4]);
        @memcpy(sign_buf[4..96], pkt.data[68..160]);
        const signature = keypair.sign(&sign_buf);
        @memcpy(pkt.data[4..68], &signature.data);

        pkt.len = 160;
        pkt.src_addr = peer.addr;

        // Kernel socket only — AF_XDP TX lacks the L3/L4 framing the raw send
        // path needs (same as every other repair request path).
        if (self.repair_socket) |*sock| {
            const ok = sock.send(&pkt) catch return false;
            if (ok) _ = self.stats.repairs_sent.fetchAdd(1, .monotonic);
            return ok;
        }
        return false;
    }

    /// [REPAIR-INFLIGHT] timeout drain — runs immediately BEFORE
    /// checkAndRequestRepairs on BOTH drivers (core-30 repair tile Block (1)
    /// and the kernel-UDP recv-inline block), same thread as insert/remove.
    /// @prov:tvu.repair-inflight — pops up to INFLIGHT_DRAIN_MAX expired
    /// entries (head-of-FIFO = strictly
    /// oldest-first; VEX_REPAIR_TIMEOUT_MS, default 150ms; FD's inflight timeout is 80ms):
    /// a (slot, idx) the assembler STILL lacks is re-requested IMMEDIATELY at
    /// the next ROTATED peer with a FRESH nonce, BYPASSING the 200ms dedup TTL
    /// (that TTL is exactly the serial-stall the lever kills — FD re-requests
    /// on inflight expiry, not on a wall-clock dedup); a shred that landed
    /// meanwhile is dropped. Budgeted like checkAndRequestRepairs (tile budget
    /// on core 30, 2ms recv budget inline) so the kernel-UDP fallback can
    /// never starve the recv loop / XSK fill ring. Also emits the ~5s
    /// [REPAIR-INFLIGHT] stats line.
    fn drainExpiredInflight(self: *Self) void {
        const table = self.inflight orelse return;

        const budget_ns: i128 = if (self.repair_tile_active) REPAIR_TILE_BUDGET_NS else REPAIR_RECV_BUDGET_NS;
        const cycle_deadline: i128 = std.time.nanoTimestamp() + budget_ns;

        if (self.config.keypair) |keypair| {
            // Peers are fetched ONCE per drain (getRepairPeers walks the whole
            // gossip table — per-entry fetch would be O(drain × contacts));
            // the slot-advertiser preference keys on the FIRST expired entry's
            // slot, and the rotation cursor spreads successive re-requests
            // across the returned set.
            const peers_buf = tl_peers_drain[0..];
            var peers: []RepairPeer = peers_buf[0..0];
            var peers_fetched = false;

            var drained: usize = 0;
            while (drained < INFLIGHT_DRAIN_MAX) : (drained += 1) {
                const now = std.time.nanoTimestamp();
                if (now >= cycle_deadline) break;
                const e = table.popExpired(@intCast(now), self.inflight_timeout_ns) orelse break;

                // Filled while outstanding (turbine / another peer / FEC
                // recovery)? Then the timeout is moot — drop, no re-request.
                if (self.shred_assembler.hasShred(e.slot, @intCast(e.idx))) continue;

                if (!peers_fetched) {
                    peers = self.getRepairPeers(e.slot, peers_buf[0..]);
                    peers_fetched = true;
                }
                if (peers.len == 0) break; // no transport targets — dedup path retries later

                // NEXT rotated peer, skipping the one that just timed out
                // (when there is any alternative) — the whole point is to
                // reach a DIFFERENT candidate holder.
                self.inflight_rerequest_rot +%= 1;
                var pi: usize = @intCast(self.inflight_rerequest_rot % peers.len);
                if (peers.len > 1 and std.mem.eql(u8, &peers[pi].pubkey, &e.peer_pk)) pi = (pi + 1) % peers.len;
                const peer = peers[pi];

                const nonce = self.nextInflightNonce();
                if (self.sendWindowIndexTo(keypair, peer, e.slot, e.idx, nonce)) {
                    table.insert(nonce, e.slot, e.idx, peer.pubkey, @intCast(std.time.nanoTimestamp()));
                    if (self.peerScoreEntry(peer.pubkey)) |sc| sc.req_cnt +|= 1;
                    self.inflight_rerequests += 1;
                    // Refresh the dedup stamp (same key layout as
                    // shouldRequestRepair) so the ordinary 200ms path doesn't
                    // immediately DUPLICATE the re-request we just made —
                    // bypass means "the TTL can't block us", not "we and the
                    // TTL both fire".
                    const key: u128 = (@as(u128, e.slot) << 32) | @as(u128, e.idx);
                    self.repair_dedup.put(key, @intCast(now)) catch {};
                }
            }
        }

        // ~5s stats line: outstanding / re-requests / matched fills / mean RTT
        // / dead peers — the lever's whole observable surface in one marker.
        const snow = std.time.nanoTimestamp();
        if (snow - self.inflight_last_stats_ns > 5 * std.time.ns_per_s) {
            self.inflight_last_stats_ns = snow;
            var dead_peers: usize = 0;
            var it = self.peer_scores.valueIterator();
            while (it.next()) |sc| {
                if (sc.req_cnt > PEER_DEAD_MIN_REQS and sc.res_cnt == 0) dead_peers += 1;
            }
            const mean_rtt_ms: u64 = if (self.inflight_rtt_cnt > 0)
                self.inflight_rtt_sum_ns / self.inflight_rtt_cnt / std.time.ns_per_ms
            else
                0;
            std.log.warn("[REPAIR-INFLIGHT] outstanding={d} rerequests={d} fills_matched={d} mean_rtt_ms={d} dead_peers={d} scored_peers={d}", .{
                table.count(), self.inflight_rerequests, self.inflight_fills_matched, mean_rtt_ms, dead_peers, self.peer_scores.count(),
            });
        }
    }

    /// HYPER-CHARGE: Increased from 6 to 20 peers per missing shred.
    /// We have 760+ peers and bandwidth headroom — saturate the repair responses.
    const REPAIR_FANOUT: usize = 6; // Peers to ask per missing shred (was 20 but round-robin meant each shred only went to 1)

    pub fn requestRepairs(self: *Self, slot: core.Slot, missing_indices: []const u32) !void {
        if (self.repair_socket == null and self.repair_io == null) {
            // Only warn occasionally to limit spam
            const count = self.stats.repairs_sent.load(.monotonic);
            if (@mod(count, 100) == 0) {
                std.log.debug("[REPAIR] No repair transport available (socket and IO are null)\n", .{});
            }
            return;
        }
        const keypair = self.config.keypair orelse {
            std.log.debug("[REPAIR-DEBUG] requestRepairs returning: keypair is null\n", .{});
            return;
        };
        const peers_buf = tl_peers_request[0..];
        const repair_peers = self.getRepairPeers(slot, peers_buf[0..]);
        if (repair_peers.len == 0) {
            const count = self.stats.repairs_sent.load(.monotonic);
            if (@mod(count, 100) == 0) {
                std.log.debug("[REPAIR] requestRepairs: no repair peers found for slot {d}\n", .{slot});
            }
            return;
        }
        const timestamp_ms: u64 = @intCast(std.time.milliTimestamp());
        // [REPAIR-INFLIGHT] gated OFF: the historical SHARED per-call nonce
        // (@truncate of the ms timestamp) — byte-identical behavior. Gated ON:
        // each request below draws a UNIQUE nonce from the tile-owned monotonic
        // counter instead. @prov:tvu.repair-inflight — nonce identifies the request so the
        // response can be matched back — a shared nonce can't attribute which
        // peer answered, which the whole inflight/RTT design depends on.
        const shared_nonce: u32 = @truncate(timestamp_ms);
        const peers_to_use = @min(REPAIR_FANOUT, repair_peers.len);

        // ── PRIMARY ROOT FIX (2026-06-14): SMALL-MISSING-SET PER-SHRED FANOUT ──
        // ROOT CAUSE of the AF_XDP catch-up DELINQUENCY (proven from the live
        // incident log): NOT a phantom
        // completion index. The completion bound is correct and authenticated —
        // the wedge shape is knows_last=TRUE with a SINGLE missing INTERIOR data
        // shred (e.g. [REPAIR-STUCK] slot=415398209 missing={260}), and that
        // shred provably exists cluster-wide (a singleton hole means every other
        // index up to last_index was received). The carrier is SLOW REPAIR
        // CONVERGENCE: each such singleton took ~13s to fill (resp_for_slot held
        // FLAT at 67 while requests for idx 260 climbed 54→69 → ~15 requests for
        // that exact index produced ZERO new responses), and thousands of these
        // serialized stalls mean catch-up never reaches the tip → delinquent.
        //
        // The defect is in TARGETING: the old "1 shred → exactly 1 peer"
        // round-robin (`peer_idx = i % peers_to_use`) means a SINGLETON missing
        // set (i==0) is ALWAYS requested from `repair_peers[0]` only. Combined
        // with slot-aware getRepairPeers (HEAD 7c8621c) returning advertisers in
        // a FIXED order, repair_peers[0] is the SAME advertiser every cycle —
        // and WindowIndex serves NOTHING when the asked peer lacks that exact
        // shred (handleWindowIndexRequest:2082 sends no negative ack). So a
        // singleton hole is hammered at one non-holder until turbine/another
        // path happens to deliver it (~13s later). 1:1 round-robin is correct
        // for LARGE missing sets (avoids 6× duplication across hundreds of
        // shreds); it is pathological for a small set where one non-holder
        // stalls the whole slot.
        //
        // FIX (Agave/FD-canonical "few missing ⇒ ask several peers per shred"):
        // request EACH missing index from ALL `peers_to_use` peers in one cycle
        // so a holder is reached on the first cycle instead of after many
        // single-peer retries — but ONLY for the current `stuck_slot` (which the
        // BRIDGE-DIAG block sets to the LOWEST in-progress / freeze-BLOCKING slot
        // each cycle, not a slot that has already been stuck 10s) with a SMALL
        // missing set. So exactly ONE slot/cycle can fan out. CRITICAL
        // (anti-amplification): fanout is gated on `slot == stuck_slot` — NOT on
        // missing-set size alone. Healthy
        // catch-up slots are FULL of small missing sets (BRIDGE-DIAG shows
        // missing=1,3,3,6... everywhere) and fill fine via 1:1 (their
        // resp_for_slot climbs); fanning ALL of them ×peers_to_use would be an
        // O(slots) 6× repair-traffic amplification = the very recv-starvation /
        // keypair.sign() CPU-saturation that caused the original AF_XDP collapse
        // (memory: O(slots) repair work starves recvZeroCopy → RX overflow →
        // NIC-drop → collapse). Gating to the single stuck slot makes the extra
        // traffic O(1): at most SMALL_MISSING_FANOUT * peers_to_use (<= 4*6 = 24)
        // packets/cycle for ONE slot — negligible vs AGAVE_MAX_REPAIR_LENGTH=512,
        // and it ENDS the ~13s-per-hole serial stall (the proven slow-convergence
        // delinquency driver). For every other slot, keep the EXACT 1:1
        // round-robin (no duplication regression). A per-call rotation offset
        // (rot) also moves the large-set start peer each call so no single
        // advertiser is permanently pinned to index 0. CONSERVATIVE: this only
        // changes WHICH peers a missing index is requested from + HOW MANY — it
        // never changes completion, freeze, the FEC/merkle gate, or what is
        // accepted; a shred still only lands via the verified ingest path.
        const SMALL_MISSING_FANOUT: usize = 4;
        const is_stuck_slot = slot == self.stuck_slot.load(.acquire);
        const fanout_all = is_stuck_slot and missing_indices.len <= SMALL_MISSING_FANOUT;
        // Per-call rotation so the large-set 1:1 mapping (and the small-set
        // start) is not pinned to advertiser[0] every cycle.
        const RepairRot = struct {
            var n: u64 = 0;
        };
        const rot: usize = @intCast(RepairRot.n % peers_to_use);
        RepairRot.n +%= 1;

        for (missing_indices, 0..) |shred_idx, i| {
            // Pure, KAT-tested peer-selection mapping (repair_targeting.zig):
            // SMALL stuck-slot set → ask every peer for this index; otherwise
            // exactly one peer (round-robin, rotated by `rot` so peer[0] isn't
            // pinned). Width-1 for every non-fanout index ⇒ no amplification.
            const pr = repair_targeting.peerRange(i, peers_to_use, rot, fanout_all);

            var pj: usize = pr.lo;
            while (pj < pr.hi) : (pj += 1) {
                const peer = repair_peers[pj];

                // [REPAIR-INFLIGHT] per-REQUEST unique nonce when gated ON
                // (see shared_nonce above); the historical shared nonce
                // otherwise — same bytes, same signing domain layout.
                const nonce: u32 = if (self.repair_inflight_enabled)
                    self.nextInflightNonce()
                else
                    shared_nonce;

                var pkt = packet.Packet.init();
                // Message type: 8 = REPAIR_WINDOW_INDEX (4 bytes LE)
                std.mem.writeInt(u32, pkt.data[0..4], 8, .little);
                // Sender pubkey (bytes 68-99)
                @memcpy(pkt.data[68..100], &keypair.public.data);
                // Recipient pubkey (bytes 100-131)
                @memcpy(pkt.data[100..132], &peer.pubkey);
                // Timestamp in ms (bytes 132-139)
                std.mem.writeInt(u64, pkt.data[132..140], timestamp_ms, .little);
                // Nonce (bytes 140-143)
                std.mem.writeInt(u32, pkt.data[140..144], nonce, .little);
                // Slot (bytes 144-151)
                std.mem.writeInt(u64, pkt.data[144..152], slot, .little);
                // Shred index (bytes 152-159)
                std.mem.writeInt(u64, pkt.data[152..160], shred_idx, .little);

                // Sign bytes[0..4] + bytes[68..160] (type + everything after signature)
                var sign_buf: [96]u8 = undefined;
                @memcpy(sign_buf[0..4], pkt.data[0..4]);
                @memcpy(sign_buf[4..96], pkt.data[68..160]);
                const signature = keypair.sign(&sign_buf);
                @memcpy(pkt.data[4..68], &signature.data);

                pkt.len = 160;
                pkt.src_addr = peer.addr;

                // Always use kernel socket for repair sends — AF_XDP send path lacks
                // ETH/IP/UDP framing required for raw socket TX. The kernel socket
                // handles all L3/L4 framing automatically via sendto().
                var sent = false;
                if (self.repair_socket) |*sock| {
                    sent = sock.send(&pkt) catch continue;
                }

                // @prov:tvu.repair-inflight — record the outstanding request after a
                // successful send. Fixed pool + reserved score map
                // ⇒ no allocation here. Same thread as the response path.
                if (self.repair_inflight_enabled and sent) {
                    if (self.inflight) |table| {
                        table.insert(nonce, slot, shred_idx, peer.pubkey, @intCast(std.time.nanoTimestamp()));
                    }
                    if (self.peerScoreEntry(peer.pubkey)) |sc| sc.req_cnt +|= 1;
                }

                _ = self.stats.repairs_sent.fetchAdd(1, .monotonic);
            }

            // Update maximum slot seen (atomic max) - with sanity check
            if (slot < 1_000_000_000) {
                var current_max = self.stats.max_slot_seen.load(.monotonic);
                while (slot > current_max) {
                    current_max = self.stats.max_slot_seen.cmpxchgWeak(
                        current_max,
                        slot,
                        .monotonic,
                        .monotonic,
                    ) orelse break;
                }
            }
        }

        // Log first request for diagnostics
        if (missing_indices.len > 0) {
            const total_sent = self.stats.repairs_sent.load(.monotonic);
            if (@mod(total_sent, 500) == 0) {
                std.log.debug("[REPAIR] Targeted {d} shreds for slot {d} across {d} peers ({s})\n", .{
                    missing_indices.len,                                                                                   slot, peers_to_use,
                    if (fanout_all) @as([]const u8, "small-set per-shred fanout") else @as([]const u8, "1:1 round-robin"),
                });
            }
        }
    }

    /// d27k (2026-05-11): set the snapshot root slot so the turbine-seeded
    /// catchup burst knows what gap to close. Called once by main.zig after
    /// snapshot load completes, before tvu_svc.start().
    pub fn setCatchupRoot(self: *Self, root_slot: u64) void {
        self.catchup_root_slot = root_slot;
    }

    /// d27k (2026-05-11): turbine-seeded catchup repair burst.
    ///
    /// @prov:tvu.catchup-repair-burst — canonical pattern. On the first
    /// turbine shred ever received, fire `RepairHighestWindowIndex` requests
    /// at every slot in `(snapshot_root, turbine_slot0]` to bootstrap the
    /// repair pipeline. Repair responses then flow back through the normal
    /// shred-assembler + replay pipeline.
    ///
    /// This REPLACES Vexor's prior sequential RPC catchup loop, which was
    /// an architectural anti-pattern (~1-2 slots/sec end-to-end, tail-chase
    /// pass-over-pass gap growth, dependent on public-RPC rate limits).
    /// Repair-based catchup runs at hundreds-to-thousands of slots/sec —
    /// requests are UDP, parallel across peers, no fork+curl contention.
    ///
    /// Called from two places — (1) processShred on first turbine shred, and
    /// (2) the periodic repair loop in checkAndRequestRepairs — gated by a
    /// 30-second throttle on `last_catchup_seed_fire_ms`. Re-firing as gossip
    /// warms up lets each successive burst reach more peers (typical curve:
    /// 70 peers at first-shred → 500+ peers 60s later).
    /// Minimum interval between catchup-repair burst re-fires (ms).
    /// 30s is a balance: gossip grows ~10× over the first 60-90s of startup,
    /// so re-firing every 30s gives 2-3 bursts at progressively more peers.
    /// More frequent would spam the network; less frequent would miss the
    /// gossip warm-up window.
    const CATCHUP_SEED_REFIRE_MS: i64 = 30_000;

    /// Companion catch-up lever (VEX_CATCHUP_ADAPTIVE_REFIRE, default OFF).
    /// Hard floor for the gap-proportional refire cadence — the seed burst is
    /// NEVER re-fired faster than this, no matter how large the gap.
    const CATCHUP_SEED_REFIRE_MIN_MS: i64 = 5_000;
    /// At/below this gap: NO acceleration (healthy rooting oscillation ~32 slots
    /// must never trip it) — keep the full 30s cadence.
    const CATCHUP_SEED_ACCEL_GAP: u64 = 100;
    /// At/above this gap (the SlotHashes 512-entry breach point where votes start
    /// being rejected VoteTooOld): full 5s cadence.
    const CATCHUP_SEED_ACCEL_FULL_GAP: u64 = 512;

    /// Pure, KAT-testable. Gap-proportional catch-up refire interval (ms).
    /// Monotone non-increasing in gap, clamped to [5_000, 30_000]; linear
    /// interpolation between the two anchor gaps. No overflow: span*num max =
    /// 25_000 * 411 ≈ 1.03e7, far within i64.
    fn catchupRefireIntervalMs(gap: u64) i64 {
        if (gap <= CATCHUP_SEED_ACCEL_GAP) return CATCHUP_SEED_REFIRE_MS;
        if (gap >= CATCHUP_SEED_ACCEL_FULL_GAP) return CATCHUP_SEED_REFIRE_MIN_MS;
        const span: i64 = CATCHUP_SEED_REFIRE_MS - CATCHUP_SEED_REFIRE_MIN_MS; // 25_000
        const width: i64 = @intCast(CATCHUP_SEED_ACCEL_FULL_GAP - CATCHUP_SEED_ACCEL_GAP); // 412
        const num: i64 = @intCast(gap - CATCHUP_SEED_ACCEL_GAP);
        return CATCHUP_SEED_REFIRE_MS - @divTrunc(span * num, width);
    }

    /// Recv-thread time budget for one checkAndRequestRepairs cycle (incl. the
    /// catch-up seed burst). 2026-06-14: the seed burst (up to SEED_CAP HWI sends,
    /// ~150us each) ran to completion synchronously on the recv thread → ~227ms
    /// blackout per fire → the XSK fill ring starved (fill_free=0) → NIC dropped
    /// turbine → the next slot never completed → freeze-tip wedge (dead=0). The fill
    /// ring empties somewhere under 14ms, so cap recv-thread repair work well under
    /// that. Repair just spreads over more 50ms cycles — it is not latency-critical.
    const REPAIR_RECV_BUDGET_NS: i128 = 2 * std.time.ns_per_ms;

    /// Repair budget when checkAndRequestRepairs runs on the dedicated CORE-30
    /// repair tile (repair_tile_active, AF_XDP net-tile Stage 1+). The 2ms cap
    /// above exists ONLY to keep the RECV thread free to replenish the XSK fill
    /// ring; the repair tile is a SEPARATE thread on a SEPARATE core that does NOT
    /// touch the fill ring, so applying the 2ms cap there was a pure catch-up
    /// THROTTLE — only ~10 HighestWindowIndex sends/cycle vs the 2000+ wanted, so
    /// the frontier slot's body never filled → freeze-tip wedge / delinquency.
    /// On the tile, allow most of the 50ms repair interval so the catch-up seed +
    /// per-slot body-fill dispatch at full rate (the pre-net-tile kernel-UDP binary
    /// caught up precisely because its repair ran UNBUDGETED). Diagnosis wf
    /// wn5fqhilj 2026-06-14: the 2ms cap was the PRIMARY AF_XDP catch-up regression
    /// once Stage 1 moved repair off the recv thread. ~95% duty (2ms tile sleep).
    const REPAIR_TILE_BUDGET_NS: i128 = 40 * std.time.ns_per_ms;

    fn seedCatchupRepairs(self: *Self, turbine_slot0: u64, deadline_ns: i128) void {
        // FIX (2026-06-14, AF_XDP bridge-repair wedge — live slot 415258054): anchor the
        // catch-up seed on the CONSENSUS root (accounts_db.rooted_slot — the monotonic
        // tower/supermajority root), NOT root_bank.slot (the LAST-FROZEN bank = freeze-tip,
        // non-monotonic). Under fast AF_XDP recv the tip shreds freeze a near-tip/orphan fork
        // → root_bank.slot jumps ~600 slots ABOVE the consensus root → the seed started at
        // freeze-tip+1 and SKIPPED the entire bridge (consensus_root, freeze-tip], whose slots
        // have ZERO received shreds and so are never requested anywhere (checkAndRequestRepairs
        // only walks in-progress slots; orphan only walks pending_chain) → permanent gap, root
        // never advances, pending_chain grows unbounded. This is the SAME root_bank-vs-
        // consensus_root confusion FIX #112 (collectOrphanTargets) and FIX #114 (repair budget
        // filter, ~line 3309) already fixed — seedCatchupRepairs was the un-migrated straggler.
        // CANONICAL: Agave roots repair on bank_forks.root() (repair_weight.rs set_root, which
        // asserts monotonic) and Firedancer on fd_forest_root_slot — both the consensus root,
        // NEVER the freeze-tip. FIX #48's old citation of repair_weight.set_root(root_bank.slot())
        // was right in INTENT but Vexor's `root_bank` field is the freeze-tip, not Agave's rooted
        // bank. Fall back to catchup_root_slot (boot snapshot root) only before accounts_db is
        // wired at very early bootstrap.
        var root_slot = self.catchup_root_slot;
        if (self.slot_sink) |rs| {
            if (rs.accountsDb()) |db| {
                if (db.rooted_slot > root_slot) root_slot = db.rooted_slot;
            }
        }
        if (root_slot == 0 or turbine_slot0 <= root_slot + 1) {
            return; // either uninitialized or no gap to close
        }

        // d27l: throttle re-fires. The seed is called both from processShred
        // (on first turbine shred) AND from the periodic repair loop
        // (checkAndRequestRepairs) so it can re-fire as gossip warms up.
        const now_ms = std.time.milliTimestamp();
        const last_fire = self.last_catchup_seed_fire_ms.load(.acquire);
        // Companion lever (VEX_CATCHUP_ADAPTIVE_REFIRE): shorten the refire interval
        // toward a 5s floor as the gap grows so a deep gap is re-seeded ~6x more often
        // than every 30s. Default OFF ⇒ refire_ms stays 30_000 ⇒ byte-identical.
        // Per-fire dispatch budget (deadline_ns) UNCHANGED — identical bursts, more of
        // them. gap == turbine_slot0 - root_slot - 1; the :3194 early-return guarantees
        // turbine_slot0 > root_slot + 1, so this is >= 1 (no underflow).
        var refire_ms: i64 = CATCHUP_SEED_REFIRE_MS;
        if (self.catchup_adaptive_refire) {
            refire_ms = catchupRefireIntervalMs(turbine_slot0 - root_slot - 1);
        }
        if (last_fire != 0 and now_ms - last_fire < refire_ms) return;
        if (refire_ms < CATCHUP_SEED_REFIRE_MS) {
            std.log.warn(
                "[CATCHUP-REFIRE] adaptive fast cadence engaged: gap={d} refire_ms={d} (floor={d})",
                .{ turbine_slot0 - root_slot - 1, refire_ms, CATCHUP_SEED_REFIRE_MIN_MS },
            );
        }
        if (self.last_catchup_seed_fire_ms.cmpxchgStrong(last_fire, now_ms, .seq_cst, .seq_cst) != null) {
            return; // another thread already incremented; skip duplicate fire
        }

        // d27l: stop re-seeding once root has caught up past turbine_slot0.
        // FIX (2026-06-14): key this on the CONSENSUS root (accounts_db.rooted_slot), NOT
        // root_bank.slot (freeze-tip) — same fix as the anchor above. With the freeze-tip a
        // near-tip orphan freeze (freeze-tip >= turbine_slot0) would PREMATURELY self-terminate
        // the seed while the consensus root is still ~600 slots behind, leaving the bridge
        // unrepaired forever. Only the consensus root advancing past turbine_slot0 means the
        // catch-up gap is genuinely closed.
        if (self.slot_sink) |rs| {
            if (rs.accountsDb()) |db| {
                if (db.rooted_slot >= turbine_slot0) return;
            }
        }

        // d27k-diag: probe how many repair peers gossip has discovered at this
        // instant. If 0, our HighestWindowIndex requests no-op silently (per
        // `requestHighestWindowIndex` at line 2068: `if (repair_peers.len == 0) return`).
        const peers_buf = tl_peers_seed[0..];
        const peers_now = self.getRepairPeers(turbine_slot0, peers_buf[0..]);
        std.log.warn("[CATCHUP-SEED-DIAG] gossip peer count at seed firing: {d}", .{peers_now.len});

        const gap = turbine_slot0 - root_slot - 1;
        // d27s (2026-05-11): cap seed-burst to 2048 slots, not 20000.
        // Each requestHighestWindowIndex sends to 6 peers serially → ~250μs
        // per slot under load (NIC dispatch + gossip lookup). A 20000-slot
        // burst takes ~30s of wall time and BLOCKS the entire repair loop
        // (seedCatchupRepairs is called synchronously from checkAndRequestRepairs).
        // While the burst runs, no WindowIndex requests are issued for ANY
        // slot, so near-root slots stay at count=1 (only HWI response) and
        // never make progress.
        //
        // With cap=2048, burst takes ~3s wall, repair loop resumes promptly,
        // WindowIndex fill-in flows. Re-fire every 30s walks deeper into the
        // catchup range as gossip warms. Slots beyond root+2048 still get HWI
        // via the regular checkAndRequestRepairs CASE 2 path (line ~2767:
        // requestHighestWindowIndex for slots without knows_last_shred).
        const SEED_CAP: u64 = 2048;
        const seed_count = @min(gap, SEED_CAP);

        std.log.warn(
            "[CATCHUP-SEED] turbine_slot0={d} root={d} gap={d}: bursting {d} HighestWindowIndex repairs to peers",
            .{ turbine_slot0, root_slot, gap, seed_count },
        );

        var seeded: u64 = 0;
        var hole_seeded: u64 = 0;
        const end_slot = root_slot + seed_count;
        var budget_hit = false;

        // ── Phase 1 (FIX 2026-06-14, AF_XDP bridge-backfill wedge — live slot
        // 415282971, root frozen @415282970, hole @root+43): PRIORITY-seed the
        // ABSENT HOLE directly above the freeze-tip — [freeze_tip+1, lowest_in_progress).
        //
        // ROOT CAUSE of the wedge this fixes: the burst below anchors on the
        // CONSENSUS root (root_slot) and the 2ms recv-thread deadline_ns caps it
        // to ~17 dispatches/cycle. When the freeze-tip sits ABOVE the consensus
        // root by a contiguous frozen run (the normal catch-up shape — here 42
        // frozen slots 415282929..415282970), every cycle re-spent its entire
        // budget re-requesting those ALREADY-FROZEN slots and NEVER reached the
        // first absent slot (415282971). Those hole slots have zero received
        // shreds, so they are requested NOWHERE else (the per-slot WindowIndex
        // loop in checkAndRequestRepairs only walks in-progress slots; orphan
        // repair only walks pending_chain) → root could never advance → permanent
        // freeze (PR-S5-PROBE static across 2200 calls).
        //
        // The hole is exactly [freeze_tip+1, lowest_in_progress): ≤ freeze_tip is
        // frozen (skip), ≥ lowest_in_progress is already being received (handled
        // by the per-slot WindowIndex loop). Seeding the hole moves those slots
        // absent→in-progress; the per-slot loop then completes them; they freeze;
        // root advances. CANONICAL: Agave repairs the INCOMPLETE FRONTIER from
        // root (repair_service generate_repairs walks the fork tree), never
        // re-requesting complete slots — exactly this skip-frozen behaviour.
        var freeze_tip: u64 = root_slot;
        if (self.slot_sink) |rs| {
            if (rs.rootBank()) |rb| {
                if (rb.slot > freeze_tip) freeze_tip = rb.slot;
            }
        }
        const ip_stats = self.shred_assembler.inProgressStats(turbine_slot0);
        const lowest_ip: u64 = ip_stats.min_slot; // 0 ⇒ nothing in progress
        if (lowest_ip > freeze_tip + 1) {
            var hslot: u64 = freeze_tip + 1;
            while (hslot < lowest_ip) : (hslot += 1) {
                if (std.time.nanoTimestamp() >= deadline_ns) {
                    budget_hit = true;
                    break;
                }
                self.requestHighestWindowIndex(hslot, 0) catch continue;
                hole_seeded += 1;
                seeded += 1;
            }
        }

        // ── Phase 2 (broad catch-up sweep) ──
        // Sweep [root_slot+1, end_slot] in slot-ascending order. root_slot+1 anchor
        // is DELIBERATE (FIX #112/#114): root_bank.slot/freeze_tip is NON-MONOTONIC
        // (stored on every freeze, replay_stage.zig:3060) and can be an orphan-fork
        // slot ~600 slots ABOVE the consensus root, with zero-shred canonical bridge
        // slots (root_slot, freeze_tip] that are requested NOWHERE else — anchoring
        // above freeze_tip would abandon them → permanent-gap wedge.
        //
        // NOTE 2026-06-14: a "net-new first" priority-reorder of this sweep was tried
        // (FIX A) to fix the growing-gap inefficiency (budget spent re-probing the
        // already-frozen contiguous range while the tip pulls away) but was REVERTED:
        // adversarial review proved that under the per-fire budget the net-new pass
        // always exhausts the deadline and PERMANENTLY STARVES the orphan-bridge pass
        // → re-creates the FIX #112/#114 wedge in the orphan shape. The correct fix is
        // a CONDITIONAL budget split (reserve a guaranteed slice for the zero-shred
        // bridge), deferred pending the Part-1 diagnostics that localize the actual
        // catch-up dead-end. Reverted to the safe ascending sweep here.
        var slot: u64 = root_slot + 1;
        while (!budget_hit and slot <= end_slot) : (slot += 1) {
            if (std.time.nanoTimestamp() >= deadline_ns) {
                budget_hit = true;
                break;
            }
            self.requestHighestWindowIndex(slot, 0) catch continue;
            seeded += 1;
        }
        std.log.warn("[CATCHUP-SEED] done — {d}/{d} requests dispatched (hole={d} freeze_tip={d} lowest_ip={d}){s}", .{ seeded, seed_count, hole_seeded, freeze_tip, lowest_ip, if (budget_hit) " (budget-capped)" else "" });
    }

    /// Request the HIGHEST shred a peer has for a slot (repair type 9 = HighestWindowIndex)
    /// This is how Firedancer discovers the total shred count for a slot.
    /// The peer responds with the highest shred it has >= shred_idx.
    /// That response's is_last_in_slot flag tells us the true last index.
    pub fn requestHighestWindowIndex(self: *Self, slot: core.Slot, shred_idx: u64) !void {
        if (self.repair_socket == null and self.repair_io == null) return;
        const keypair = self.config.keypair orelse return;
        const peers_buf = tl_peers_highest[0..];
        const repair_peers = self.getRepairPeers(slot, peers_buf[0..]);
        if (repair_peers.len == 0) return;

        const timestamp_ms: u64 = @intCast(std.time.milliTimestamp());
        const nonce: u32 = @truncate(timestamp_ms);
        // HWI needs fast response during catch-up — ask 6 peers for redundancy
        const hwi_fanout = @min(6, repair_peers.len);

        for (repair_peers[0..hwi_fanout]) |peer| {
            var pkt = packet.Packet.init();
            // Message type: 9 = REPAIR_HIGHEST_WINDOW_INDEX (4 bytes LE)
            std.mem.writeInt(u32, pkt.data[0..4], 9, .little);
            // Sender pubkey (bytes 68-99)
            @memcpy(pkt.data[68..100], &keypair.public.data);
            // Recipient pubkey (bytes 100-131)
            @memcpy(pkt.data[100..132], &peer.pubkey);
            // Timestamp in ms (bytes 132-139)
            std.mem.writeInt(u64, pkt.data[132..140], timestamp_ms, .little);
            // Nonce (bytes 140-143)
            std.mem.writeInt(u32, pkt.data[140..144], nonce, .little);
            // Slot (bytes 144-151)
            std.mem.writeInt(u64, pkt.data[144..152], slot, .little);
            // Shred index (bytes 152-159) — peer returns highest >= this
            std.mem.writeInt(u64, pkt.data[152..160], shred_idx, .little);

            // Sign bytes[0..4] + bytes[68..160] (type + everything after signature)
            var sign_buf: [96]u8 = undefined;
            @memcpy(sign_buf[0..4], pkt.data[0..4]);
            @memcpy(sign_buf[4..96], pkt.data[68..160]);
            const signature = keypair.sign(&sign_buf);
            @memcpy(pkt.data[4..68], &signature.data);

            pkt.len = 160;
            pkt.src_addr = peer.addr;

            // Always use kernel socket for repair sends — AF_XDP send path lacks
            // ETH/IP/UDP framing required for raw socket TX. The kernel socket
            // handles all L3/L4 framing automatically via sendto().
            if (self.repair_socket) |*sock| {
                _ = sock.send(&pkt) catch continue;
            }

            _ = self.stats.repairs_sent.fetchAdd(1, .monotonic);
        }

        if (self.stats.repairs_sent.load(.monotonic) < 20) std.log.debug("[REPAIR] HighestWindowIndex for slot {d} (>= idx {d}) to {d} peers\n", .{
            slot, shred_idx, hwi_fanout,
        });
    }
    /// Request the ancestry of an orphan slot (repair type 10 = Orphan).
    /// The peer responds with the highest shred of each of the first
    /// MAX_ORPHAN_REPAIR_RESPONSES (=11, agave-4.1) parents — which lets us
    /// DISCOVER + chain the missing ancestor slots so normal window repair can
    /// fill them. This is the FETCH half of the catch-up fix: without it the
    /// 0-shred bridge-ancestors between root and tip are never discovered, the
    /// CHAIN-DEFER pile grows unbounded, and root never advances.
    ///
    /// Wire bytes built by orphan_request.zig (disc=10, 152B) — byte-exact vs
    /// agave-4.1.0-beta.1 serve_repair.rs:429 (Orphan=10) + RepairRequestHeader
    /// :372. NEW code: does NOT touch the proven WindowIndex/HighestWindowIndex
    /// builders. Per-request nonce + cross-tick peer rotation (the CHAIN-DEFER
    /// trigger re-emits with a fresh getRepairPeers sample) so one silent
    /// 4.0.0-rc.1 burst-DataBudget peer cannot stall a slot.
    pub fn requestOrphan(self: *Self, slot: core.Slot) !void {
        if (self.repair_socket == null and self.repair_io == null) return;
        const keypair = self.config.keypair orelse return;
        const peers_buf = tl_peers_orphan[0..];
        const repair_peers = self.getRepairPeers(slot, peers_buf[0..]);
        if (repair_peers.len == 0) return;

        const timestamp_ms: u64 = @intCast(std.time.milliTimestamp());
        // Small fan-out for redundancy against silent peers; the trigger
        // controls cadence and rotates peers across ticks.
        const orphan_fanout = @min(@as(usize, 4), repair_peers.len);

        for (repair_peers[0..orphan_fanout], 0..) |peer, i| {
            // Distinct nonce per request (not the WindowIndex path's shared
            // batch nonce). Vexor doesn't nonce-gate responses, but distinct
            // nonces keep us Agave-canonical + future-proof.
            const nonce: u32 = @truncate(timestamp_ms +% @as(u64, @intCast(i)));

            var pkt = packet.Packet.init();
            orphan_request.buildUnsigned(
                pkt.data[0..orphan_request.REQUEST_LEN],
                keypair.public.data,
                peer.pubkey,
                timestamp_ms,
                nonce,
                slot,
            );
            // Sign domain = [0..4] ++ [68..152]; signature goes in [4..68].
            var sign_buf: [orphan_request.SIGN_DOMAIN_LEN]u8 = undefined;
            orphan_request.signDomain(pkt.data[0..orphan_request.REQUEST_LEN], &sign_buf);
            const signature = keypair.sign(&sign_buf);
            @memcpy(pkt.data[4..68], &signature.data);

            pkt.len = @intCast(orphan_request.REQUEST_LEN);
            pkt.src_addr = peer.addr;

            // Kernel socket only — AF_XDP TX lacks the L3/L4 framing the raw
            // send path needs (same as the other repair request paths).
            if (self.repair_socket) |*sock| {
                _ = sock.send(&pkt) catch continue;
            }
            _ = self.stats.repairs_sent.fetchAdd(1, .monotonic);
        }

        if (self.stats.repairs_sent.load(.monotonic) < 40)
            std.log.debug("[REPAIR] Orphan(10) for slot {d} to {d} peers\n", .{ slot, orphan_fanout });
    }

    /// Repair peer info (address + pubkey for signed requests)
    pub const RepairPeer = struct {
        addr: packet.SocketAddr,
        pubkey: [32]u8,
    };
    /// Get repair peers for a slot (nodes that likely have it)
    /// Queries gossip for peers with valid serve_repair addresses
    ///
    /// Collects up to MAX_REPAIR_PEERS and randomly samples from available peers
    /// to distribute repair load across the network.
    const MAX_REPAIR_PEERS: usize = 2000; // @prov:tvu.repair-peers-cap — was 500, 2000 is a safe increase

    // Per-site threadlocal repair peer-selection scratch (perf, 2026-07-08): each
    // caller below had a ~112KB stack local (`[MAX_REPAIR_PEERS]RepairPeer`) that
    // tripped __zig_probe_stack (~7% self) on every call in the hot repair path
    // (and cascaded into checkAndRequestRepairs/drainRepairPackets via inlining).
    // Moved off-stack. DISTINCT per site: seedCatchupRepairs nests
    // requestHighestWindowIndex, so a shared buffer would alias mid-use; threadlocal
    // also keeps the two repair threads independent (no lock). Behaviour-identical —
    // each fn fills [0..n] via getRepairPeers and uses only that returned slice;
    // stale bytes beyond n are never read. (`all_peers` inside getRepairPeers is
    // already a struct-scoped static, not stack — left as-is.)
    threadlocal var tl_peers_drain: [MAX_REPAIR_PEERS]RepairPeer = undefined;
    threadlocal var tl_peers_request: [MAX_REPAIR_PEERS]RepairPeer = undefined;
    threadlocal var tl_peers_seed: [MAX_REPAIR_PEERS]RepairPeer = undefined;
    threadlocal var tl_peers_highest: [MAX_REPAIR_PEERS]RepairPeer = undefined;
    threadlocal var tl_peers_orphan: [MAX_REPAIR_PEERS]RepairPeer = undefined;

    /// THREAD-SAFE (2026-06-14, Stage-1 prereq): writes the selected peers into
    /// the CALLER-PROVIDED `out` buffer and returns `out[0..n]` — never a slice
    /// into shared/static storage. The entire body runs under
    /// `self.repair_peers_mutex` so a second concurrent caller (the core-30
    /// repair control tile) can neither tear the sampling statics nor race the
    /// all_peer_count guard against the modulo (the old function-local-static
    /// version returned an aliased slice into `S.repair_peers` and could divide
    /// by zero when a second thread reset `all_peer_count` to 0 between the
    /// `> 0` guard and `% all_peer_count`). Callers pass their own on-stack
    /// `[MAX_REPAIR_PEERS]RepairPeer` and may iterate the returned slice freely
    /// after the call — it is theirs.
    fn getRepairPeers(self: *Self, slot: core.Slot, out: []RepairPeer) []RepairPeer {
        // SLOT-AWARE REPAIR (2026-06-14): `slot` is no longer discarded. After the
        // candidate set is built exactly as before, we PARTITION it by ClusterSlots
        // membership and place advertisers of `slot` FIRST in `out` (topping up with
        // non-advertisers for liveness/diversity). When the index has NO advertiser
        // for `slot` (cold at the very tip, before EpochSlots propagate) we fall
        // through to the EXACT pre-change golden-ratio round-robin — so a cold index
        // is byte-identical to today's behaviour (no liveness regression).
        self.repair_peers_mutex.lock();
        defer self.repair_peers_mutex.unlock();

        const out_cap = @min(MAX_REPAIR_PEERS, out.len);

        if (self.repair_peers_override.items.len > 0) {
            const n = @min(self.repair_peers_override.items.len, out_cap);
            @memcpy(out[0..n], self.repair_peers_override.items[0..n]);
            return out[0..n];
        }

        // Persistent sampling scratch (touched ONLY under repair_peers_mutex):
        // all_peers is the temp collection buffer, call_count drives the rotating
        // sample seed + periodic diagnostic cadence. The selected peers are
        // written into `out`, never into a static, so the returned slice is the
        // caller's own buffer.
        const S = struct {
            var all_peers: [8192]RepairPeer = undefined; // Temp buffer for sampling
            var all_peer_count: usize = 0;
            var call_count: u64 = 0;
        };

        // Try to get peers from gossip
        if (self.gossip_service) |gs| {
            // Collect repair peers with RELAXED filtering.
            // Only require: valid serve_repair address + matching shred_version.
            // Wallclock freshness check DISABLED — it was dropping 100% of peers
            // because our clock or snapshot epoch is offset from the network.
            S.all_peer_count = 0;
            const expected_shred_version = self.config.shred_version;

            var total_contacts: usize = 0;
            var dropped_no_port: usize = 0;
            var dropped_shred_ver: usize = 0;

            // vex-030 fix: gossip writes take gs.table.contacts_rw.lock() (exclusive).
            // Iterating without a shared lock races the HashMap internals and
            // can return zero entries even when peers are present (observed:
            // gossip.zig logs "13 total peers" while this loop sees 0).
            gs.table.contacts_rw.lockShared();
            defer gs.table.contacts_rw.unlockShared();

            var iter = gs.table.contacts.iterator();
            while (iter.next()) |entry| {
                const info = entry.value_ptr;
                total_contacts += 1;

                // Must have a valid serve_repair address
                if (info.serve_repair_addr.port() == 0) {
                    dropped_no_port += 1;
                    continue;
                }

                // Must match our shred version (skip mismatched, allow zero)
                if (expected_shred_version > 0 and info.shred_version != expected_shred_version and info.shred_version != 0) {
                    dropped_shred_ver += 1;
                    continue;
                }

                // Wallclock check DISABLED — was causing 100% peer drop
                // TODO: Re-enable once clock sync is verified

                if (S.all_peer_count < S.all_peers.len) {
                    S.all_peers[S.all_peer_count] = .{ .addr = info.serve_repair_addr, .pubkey = info.pubkey.data };
                    S.all_peer_count += 1;
                }
            }

            // Periodic gossip state diagnostic (every ~10 seconds = every 20 calls)
            // d27l-diag (2026-05-11): promoted to .warn so we can see live
            // repair-peer-count and filter-drop reasons after the vex-031
            // gossip-table fix. Decisive for "is gossip getting peers?" vs
            // "is our filter dropping them?".
            S.call_count += 1;
            if (@mod(S.call_count, 20) == 1) {
                std.log.debug("[GOSSIP-STATE] Total contacts: {d}, Valid repair_peers: {d}, Dropped: no_port={d} shred_ver={d}", .{
                    total_contacts, S.all_peer_count, dropped_no_port, dropped_shred_ver,
                });
            }

            // ── STAKE-WEIGHTED SELECTION (gated -Drepair_stake_weighting, default OFF) ──
            // @prov:tvu.stake-weighted-repair-peers — when ON, choose repair
            // candidates WEIGHTED by cached epoch stake,
            // preserving the 2026-06-14 advertiser-preference as a tier. Returns null
            // to DEGRADE to the advertiser+round-robin path below (no leader_cache, no
            // cached stakes for the epoch, or OOM). NON-CONSENSUS: picks WHOM we ask,
            // never WHAT we accept. When OFF the whole branch is comptime-dead ⇒
            // byte-identical to the existing path.
            if (comptime build_options.repair_stake_weighting) {
                if (self.selectStakeWeightedRepairPeers(slot, S.all_peers[0..S.all_peer_count], out, out_cap, S.call_count)) |sel| {
                    return sel;
                }
            }

            // ── SLOT-AWARE PASS (2026-06-14) ──────────────────────────────────
            // Prefer candidates that advertise `slot` via EpochSlots gossip.
            // @prov:tvu.slot-aware-repair-pass — reduced to presence (no
            // epoch-stake term). Advertisers fill
            // `out` first; remaining slots top up from non-advertisers (preserving
            // the fanout count + diversity). If NO candidate advertises `slot`
            // (cold/tip), we fall through to the unchanged round-robin below.
            //
            // We take cluster_slots.mutex INSIDE repair_peers_mutex (consistent
            // nested order; the gossip writer takes ONLY cluster_slots.mutex, so no
            // deadlock cycle). One isAdvertiser call per candidate — short critical
            // sections (small linear scan of <=32 advertisers).
            if (S.all_peer_count > 0 and out_cap > 0) {
                // PRIMARY ROOT FIX (2026-06-14): ROTATE the advertiser scan START
                // each call. Pre-fix the first pass always started at ci=0, so the
                // SAME advertisers deterministically filled out[0..pref_count] every
                // cycle. For a slot whose only hole is a single interior shred that
                // the first few advertisers happen NOT to hold, that hole was
                // requested from the same non-holders forever (the ~13s-per-singleton
                // slow-convergence stall — see requestRepairs comment). Rotating the
                // start index (mod count) by the call counter means successive cycles
                // sample DIFFERENT advertisers, so a holder of the missing shred is
                // reached quickly. Pairs with requestRepairs' small-set fanout. Pure
                // selection diversity — same candidate set, no validation change.
                const rot_start: usize = @intCast(S.call_count % S.all_peer_count);
                var pref_count: usize = 0;
                var k: usize = 0;
                if (self.repair_inflight_enabled) {
                    // @prov:tvu.repair-inflight — peer-scoring lite: SAME
                    // rotated advertiser-first
                    // shape, but (a) peers proven DEAD by the inflight
                    // ledger (req_cnt>32, res_cnt==0) are skipped everywhere,
                    // and (b) FAST advertisers (mean matched RTT < 80ms) fill
                    // `out` before the rest — two rotated sub-passes over the
                    // same candidate set, so pass 0 ∪ pass 1 == the ungated
                    // advertiser set minus dead peers. If every advertiser is
                    // dead we fall through to the round-robin below unchanged
                    // (fail-open: scoring can down-rank, never black-hole).
                    var pass: usize = 0;
                    while (pass < 2) : (pass += 1) {
                        k = 0;
                        while (k < S.all_peer_count and pref_count < out_cap) : (k += 1) {
                            const ci = (rot_start + k) % S.all_peer_count;
                            const cand = S.all_peers[ci];
                            if (!self.cluster_slots.isAdvertiser(slot, cand.pubkey)) continue;
                            if (self.peerScoreDead(cand.pubkey)) continue;
                            if ((pass == 0) != self.peerScoreFast(cand.pubkey)) continue;
                            out[pref_count] = cand;
                            pref_count += 1;
                        }
                    }
                } else {
                    // First pass: copy advertisers of `slot` into `out` (up to out_cap),
                    // scanning all candidates but starting at the rotated offset.
                    while (k < S.all_peer_count and pref_count < out_cap) : (k += 1) {
                        const ci = (rot_start + k) % S.all_peer_count;
                        if (self.cluster_slots.isAdvertiser(slot, S.all_peers[ci].pubkey)) {
                            out[pref_count] = S.all_peers[ci];
                            pref_count += 1;
                        }
                    }
                }
                if (pref_count > 0) {
                    // Top up with non-advertisers for liveness/diversity until out_cap
                    // (also rotated so the top-up set varies across cycles).
                    var oi = pref_count;
                    k = 0;
                    while (k < S.all_peer_count and oi < out_cap) : (k += 1) {
                        const ci = (rot_start + k) % S.all_peer_count;
                        if (!self.cluster_slots.isAdvertiser(slot, S.all_peers[ci].pubkey)) {
                            // [REPAIR-INFLIGHT] (gated): dead peers don't get
                            // top-up slots either. Gate OFF ⇒ condition is
                            // never evaluated ⇒ byte-identical top-up.
                            if (self.repair_inflight_enabled and self.peerScoreDead(S.all_peers[ci].pubkey)) continue;
                            out[oi] = S.all_peers[ci];
                            oi += 1;
                        }
                    }
                    if (oi > 0 and self.stats.repairs_sent.load(.monotonic) < 5) {
                        std.log.debug("[REPAIR] slot {d}: {d} advertiser(s) preferred, {d} total selected (shred_ver={d})\n", .{ slot, pref_count, oi, expected_shred_version });
                    }
                    return out[0..oi];
                }
                // else: index cold for this slot -> fall through to round-robin.
            }

            if (S.all_peer_count > 0 and out_cap > 0) {
                // Randomly sample peers using a simple hash-based selection.
                // Selected peers go straight into the caller's `out` buffer.
                const seed = S.call_count *% 0x9E3779B97F4A7C15; // Golden ratio hash

                var peer_count: usize = 0;
                const cap = @min(out_cap, S.all_peer_count);
                const step = if (S.all_peer_count > cap)
                    S.all_peer_count / cap
                else
                    1;

                var idx: usize = @truncate(seed % S.all_peer_count);
                while (peer_count < cap) {
                    const safe_idx = @min(idx, S.all_peer_count - 1);
                    out[peer_count] = S.all_peers[safe_idx];
                    peer_count += 1;
                    idx = (idx + step) % S.all_peer_count;
                }

                // Log peer count sparingly (first time + every 60s via caller)
                if (peer_count > 0 and self.stats.repairs_sent.load(.monotonic) < 5) {
                    std.log.debug("[REPAIR] Got {d} quality peers (shred_ver={d}) from {d} total gossip\n", .{ peer_count, expected_shred_version, total_contacts });
                }
                return out[0..peer_count];
            }
        }

        // Fallback: hardcoded testnet repair peers — copied into the caller's
        // `out` buffer so the returned slice never aliases shared storage.
        std.log.debug("[REPAIR] Using fallback hardcoded peers (gossip had 0)\n", .{});
        const static_repair_peers = [_]RepairPeer{
            .{ .addr = packet.SocketAddr.ipv4(.{ 192, 155, 103, 41 }, 8013), .pubkey = [_]u8{0} ** 32 },
            .{ .addr = packet.SocketAddr.ipv4(.{ 104, 250, 133, 50 }, 8012), .pubkey = [_]u8{0} ** 32 },
            .{ .addr = packet.SocketAddr.ipv4(.{ 147, 28, 169, 89 }, 8013), .pubkey = [_]u8{0} ** 32 },
        };
        const fn_n = @min(static_repair_peers.len, out_cap);
        @memcpy(out[0..fn_n], static_repair_peers[0..fn_n]);
        return out[0..fn_n];
    }

    /// Stake-weighted repair-peer selection (gated -Drepair_stake_weighting; only
    /// reached when the flag is ON). @prov:tvu.stake-weighted-repair-peers —
    /// weight each
    /// candidate by its cached epoch stake (base .max(1) so unstaked peers stay
    /// reachable and the shuffle never degenerates to all-zero), and PRESERVE the
    /// 2026-06-14 advertiser-preference as a tier (advertisers of `slot` selected
    /// first, stake-weighted; non-advertisers stake-weighted to top up). Repair
    /// selection is NON-CONSENSUS — it chooses WHOM we ask for a missing shred,
    /// never WHAT we accept (repaired shreds still pass the full verified ingest
    /// path) — so the RNG need not be byte-exact (repair_targeting.zig
    /// header); a deterministic per-call+slot seed gives spread + reproducibility.
    ///
    /// Returns null to DEGRADE to the caller's existing advertiser+round-robin path
    /// (no leader_cache wired, no cached stakes for the epoch, or any OOM). MUST be
    /// called under repair_peers_mutex (reads the shared sampling scratch via args).
    /// Lock order: repair_peers_mutex → leader_cache.mutex (acyclic — the cache's
    /// own lockers never call back into tvu).
    fn selectStakeWeightedRepairPeers(
        self: *Self,
        slot: core.Slot,
        candidates: []const RepairPeer,
        out: []RepairPeer,
        out_cap: usize,
        call_count: u64,
    ) ?[]RepairPeer {
        // Observability for the gate-ON test: counts how often the stake-weighted
        // path is genuinely ACTIVE vs DEGRADES to the existing round-robin, and why.
        // Touched only under repair_peers_mutex (the whole method runs under it).
        const Diag = struct {
            var ok: u64 = 0;
            var no_cache: u64 = 0; // leader_cache not wired
            var no_stakes: u64 = 0; // no cached epoch stakes for this slot's epoch
            var oom: u64 = 0;
        };
        if (candidates.len == 0 or out_cap == 0) return null;
        const lc = self.leader_cache orelse {
            Diag.no_cache += 1;
            if (@mod(Diag.no_cache, 256) == 1) std.log.warn("[REPAIR-SW] DEGRADE leader_cache NOT wired (slot {d}); round-robin. counts ok={d} no_cache={d} no_stakes={d} oom={d}", .{ slot, Diag.ok, Diag.no_cache, Diag.no_stakes, Diag.oom });
            return null;
        };
        const a = self.allocator;

        // Node identities parallel to candidates (RepairPeer.pubkey IS the node
        // identity; the cached stake map is keyed by node identity — no translation).
        const node_pks = a.alloc([32]u8, candidates.len) catch return null;
        defer a.free(node_pks);
        for (candidates, node_pks) |c, *pk| pk.* = c.pubkey;

        // Cached epoch stake per candidate (0 = unknown / no cache for the epoch).
        const weights = a.alloc(u64, candidates.len) catch {
            Diag.oom += 1;
            return null;
        };
        defer a.free(weights);
        lc.fillStakesForSlot(slot, node_pks, weights);

        // @prov:tvu.stake-weighted-repair-peers — base-stake semantics: every
        // weight >= 1. If NOTHING is staked (no cached stakes for this
        // epoch), degrade so the proven round-robin handles it rather than a uniform
        // shuffle masquerading as stake-weighting.
        var any_stake = false;
        for (weights) |*w| {
            if (w.* > 0) any_stake = true;
            w.* = @max(w.*, 1);
        }
        if (!any_stake) {
            Diag.no_stakes += 1;
            if (@mod(Diag.no_stakes, 64) == 1) std.log.warn("[REPAIR-SW] DEGRADE no cached stakes (epoch of slot {d}); falling back to round-robin. counts ok={d} no_cache={d} no_stakes={d} oom={d}", .{ slot, Diag.ok, Diag.no_cache, Diag.no_stakes, Diag.oom });
            return null;
        }

        // Partition candidate indices: advertisers of `slot` first, then the rest.
        const adv = a.alloc(usize, candidates.len) catch return null;
        defer a.free(adv);
        const non = a.alloc(usize, candidates.len) catch return null;
        defer a.free(non);
        var n_adv: usize = 0;
        var n_non: usize = 0;
        for (candidates, 0..) |c, i| {
            if (self.cluster_slots.isAdvertiser(slot, c.pubkey)) {
                adv[n_adv] = i;
                n_adv += 1;
            } else {
                non[n_non] = i;
                n_non += 1;
            }
        }

        // Deterministic, per-call+slot seed (consensus-neutral; see doc-comment).
        var seed: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, seed[0..8], call_count, .little);
        std.mem.writeInt(u64, seed[8..16], @intCast(slot), .little);

        var oi: usize = 0;
        oi = fillTierWeighted(a, adv[0..n_adv], weights, candidates, out, oi, out_cap, seed) orelse {
            Diag.oom += 1;
            return null;
        };
        if (oi < out_cap) {
            oi = fillTierWeighted(a, non[0..n_non], weights, candidates, out, oi, out_cap, seed) orelse {
                Diag.oom += 1;
                return null;
            };
        }
        if (oi == 0) return null;
        Diag.ok += 1;
        if (@mod(Diag.ok, 64) == 1) std.log.warn("[REPAIR-SW] ACTIVE slot={d} adv={d} non={d} selected={d} | counts ok={d} no_cache={d} no_stakes={d} oom={d}", .{ slot, n_adv, n_non, oi, Diag.ok, Diag.no_cache, Diag.no_stakes, Diag.oom });
        return out[0..oi];
    }

    /// Fill `out[oi_in..]` (capped at out_cap) from `idxs` (indices into
    /// `candidates`), ordered by a stake-weighted shuffle of `weights[idxs[..]]`.
    /// Returns the new fill count, or null on OOM (caller degrades). All weights
    /// passed here are >= 1 (clamped by the caller) so the shuffle yields a full
    /// weighted permutation (no zero-weight tail). Helper for
    /// selectStakeWeightedRepairPeers.
    fn fillTierWeighted(
        a: std.mem.Allocator,
        idxs: []const usize,
        weights: []const u64,
        candidates: []const RepairPeer,
        out: []RepairPeer,
        oi_in: usize,
        out_cap: usize,
        seed: [32]u8,
    ) ?usize {
        if (idxs.len == 0) return oi_in;
        const tier_w = a.alloc(u64, idxs.len) catch return null;
        defer a.free(tier_w);
        for (idxs, tier_w) |gi, *w| w.* = weights[gi];

        var ws = weighted_shuffle.WeightedShuffle.init(a, tier_w) catch return null;
        defer ws.deinit();
        var rng = weighted_shuffle.ChaCha8Rng.fromSeed(seed);
        var oi = oi_in;
        var it = ws.shuffle(&rng);
        while (it.next()) |local| {
            if (oi >= out_cap) break;
            out[oi] = candidates[idxs[local]];
            oi += 1;
        }
        return oi;
    }

    /// Stage 1 (2026-06-14, AF_XDP net-tile decouple): dedicated repair/control
    /// tile, pinned to CORE 30, spawned ONLY when AF_XDP zero-copy is the active
    /// backend. Relocates the three repair-control blocks OFF the recv loop
    /// (core 4) so the named checkrep/orphan/proactive spikes can no longer block
    /// recvZeroCopy and starve the XSK fill ring. These three blocks were the
    /// dominant inline occupancy stall on the AF_XDP path; they are NOT
    /// latency-critical (repair just spreads over more cycles).
    ///
    /// CONCURRENCY (de-risked, NET-TILE-PLAN STAGE 1): every assembler accessor
    /// these blocks touch is mutex-guarded — reads (getInProgressSlots,
    /// inProgressStats) take ShredAssembler.mutex; the proactive eviction's
    /// removeSlot -> clearCompletedSlot also takes ShredAssembler.mutex. Repair
    /// is on KERNEL UDP (repair_socket), so concurrent send(tile)/recv(recv-thread)
    /// is kernel-synchronized. repair_dedup is touched ONLY by checkAndRequestRepairs
    /// + pruneRepairDedup, both of which now run exclusively on this tile (the
    /// recv-thread repair DRAIN does not touch dedup). getRepairPeers is
    /// thread-safe (commit 1: full-body mutex + caller-owned buffer). self.allocator
    /// is the same allocator replay/other threads allocate on concurrently.
    ///
    /// All throttle state is TILE-LOCAL (wall-clock, not loop_count). The original
    /// recv-loop intervals/semantics are preserved exactly: repair every
    /// config.repair_interval_ms (default 50ms), dedup prune every 5s, orphan every
    /// 500ms, proactive every 10s.
    fn repairControlLoop(self: *Self) void {
        // Phase 9: default = vex_topo table (.repair == core 30, byte-identical);
        // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(30).
        if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
            pinToCore(30);
        } else {
            _ = vex_topo.pinTile(vex_topo.LIVE, .repair, 0);
        }
        std.log.info("[REPAIR-TILE] repair/control tile started on core 30 (AF_XDP gate ON)", .{});

        // Tile-local throttle state (replaces the recv loop's self.last_repair_time_ns/
        // self.last_dedup_cleanup_ns/OrphanThrottle/last_proactive_repair/
        // proactive_repair_slot — none of those are touched by recv when the tile owns
        // these blocks).
        var last_repair_ns: u64 = 0;
        var last_dedup_cleanup_ns: u64 = 0;
        var last_orphan_ns: u64 = 0;
        var last_proactive_ns: u64 = 0;
        var proactive_repair_slot: u64 = 0;

        const repair_interval_ns = self.config.repair_interval_ms * std.time.ns_per_ms;

        while (self.running.load(.acquire)) {
            // Stage 2 (2026-06-17): DRAIN repair packets HERE — off recv core 4.
            // Large pass budget so repair responses still ingest promptly during
            // catch-up; the recv loop no longer blocks ~700ms serving repair.
            const drained = self.drainRepairPackets(&self.tile_repair_batch, 64);

            const now_ns = @as(u64, @intCast(std.time.nanoTimestamp()));

            // ── Block (1): repair cycle (recv loop tvu.zig:3014-3026) ──────────
            if (now_ns > last_repair_ns + repair_interval_ns) {
                // [REPAIR-INFLIGHT] (gated): drain expired outstanding requests
                // FIRST — timed-out (slot, idx) holes are re-requested at a
                // different peer before the ordinary budget is spent.
                if (self.repair_inflight_enabled) self.drainExpiredInflight();
                self.checkAndRequestRepairs(self.config.max_repair_slots) catch {};
                // fix/chain-defer-tip-guard: drain any continuation slot the
                // CHAIN-WAKE fallback flagged (its evicted bytes were unavailable)
                // and issue a window re-fetch so replay can resume past the freeze
                // tip. Lock-free take; no-op (null) in healthy operation.
                if (self.slot_sink) |rs| {
                    if (rs.takeContinuationRepair()) |cslot| {
                        var boot_idx: [8]u32 = undefined;
                        for (&boot_idx, 0..) |*idx, i| idx.* = @intCast(i);
                        self.requestRepairs(cslot, &boot_idx) catch {};
                        std.log.warn("[CHAIN-WAKE-FALLBACK] tvu window-repair issued for continuation slot {d}", .{cslot});
                    }
                }
                last_repair_ns = now_ns;

                // Periodically prune dedup cache (every 5 seconds)
                if (now_ns > last_dedup_cleanup_ns + 5 * std.time.ns_per_s) {
                    self.pruneRepairDedup();
                    last_dedup_cleanup_ns = now_ns;
                }
            }

            // ── Block (2): ORPHAN REPAIR (recv loop tvu.zig:3040-3059) ─────────
            // Throttled ~500ms; bounded MAX_ORPHANS=5 nearest-root-first.
            if (now_ns > last_orphan_ns + 500 * std.time.ns_per_ms) {
                last_orphan_ns = now_ns;
                if (self.slot_sink) |rs| {
                    const targets: ?[]u64 = rs.collectOrphanTargets(self.allocator, 5) catch null;
                    if (targets) |ts| {
                        defer self.allocator.free(ts);
                        for (ts) |orphan_slot| {
                            self.requestOrphan(orphan_slot) catch {};
                        }
                        if (ts.len > 0 and self.stats.repairs_sent.load(.monotonic) < 400)
                            std.log.warn("[ORPHAN-REPAIR] emitted Orphan(10) for {d} gap-bottom slot(s) (nearest-root)", .{ts.len});
                    }
                }
            }

            // ── Block (3): PROACTIVE REPAIR (recv loop tvu.zig:3147-3208) ──────
            // Lightweight discovery of NEW slots: probe 5 slots ahead every 10s
            // with just indices 0-7, then evict OLD stale slots (only in normal
            // mode, real_gap <= 50).
            if (now_ns > last_proactive_ns + 10 * std.time.ns_per_s) {
                const max_seen = self.stats.max_slot_seen.load(.monotonic);
                if (max_seen > 0 and max_seen < 1_000_000_000) {
                    var bootstrap_indices: [8]u32 = undefined;
                    for (&bootstrap_indices, 0..) |*idx, i| {
                        idx.* = @intCast(i);
                    }

                    var advance: u64 = 1;
                    while (advance <= 5) : (advance += 1) {
                        const target_slot = max_seen +| advance;
                        if (target_slot != proactive_repair_slot) {
                            self.requestRepairs(target_slot, &bootstrap_indices) catch |err| {
                                std.log.debug("[TVU proactive-repair] requestRepairs err: {any}\n", .{err});
                            };
                        }
                    }
                    proactive_repair_slot = max_seen + 1;

                    // Distance-from-root catchup-mode gate (d27v): only evict in
                    // normal mode; during catch-up the time-based sweeper handles it.
                    var real_gap: u64 = std.math.maxInt(u64);
                    if (self.slot_sink) |rs| {
                        if (rs.rootBank()) |rb| {
                            real_gap = if (max_seen > rb.slot) max_seen - rb.slot else 0;
                        }
                    }
                    if (real_gap <= 50) {
                        const stale_slots = self.shred_assembler.getInProgressSlots() catch &[_]u64{};
                        defer self.allocator.free(stale_slots);
                        for (stale_slots) |stale_slot| {
                            if (stale_slot + STALE_SLOT_THRESHOLD < max_seen) {
                                self.shred_assembler.removeSlot(stale_slot);
                            }
                        }
                    }
                }
                last_proactive_ns = now_ns;
            }

            // Poll fast while repair traffic is flowing; sleep only when idle so
            // repair-response ingest stays low-latency during catch-up.
            if (drained.responses + drained.requests == 0) {
                std.Thread.sleep(2 * std.time.ns_per_ms);
            }
        }

        std.log.info("[REPAIR-TILE] repair/control tile stopped", .{});
    }

    /// Run the TVU receive loop (call from dedicated thread)
    pub fn run(self: *Self) void {
        std.log.debug("[TVU-THREAD] run() called, starting...\n", .{});
        self.running.store(true, .release);

        // ═══════════════════════════════════════════════════════════════
        // CPU PINNING: Pin this receive thread to a dedicated core.
        // @prov:tvu.core-pinning — pin to core 4 (CCD-aware layout) to avoid
        // contention with snapshot loading, gossip, and replay threads.
        // ═══════════════════════════════════════════════════════════════
        // Phase 9: default = vex_topo table (.recv == core 5 since the 2026-06-23
        // cores-0-4 wall-off; was core 4). VEX_LEGACY_PINS / -Dlegacy_pins reverts
        // to the inline literal — kept in sync at 5 so the escape hatch also lands
        // inside the cpuset (cpus=5-31); pinToCore(4) would EINVAL under the cpuset.
        if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
            pinToCore(5);
        } else {
            _ = vex_topo.pinTile(vex_topo.LIVE, .recv, 0);
        }

        // 2026-06-14 CONFIRMED FIX: dedicated jemalloc arena for this recv thread so
        // its hot-path allocs never wait on the shared arena lock (the ~212ms stall
        // that wedged AF_XDP catch-up). AF_XDP-gated → kernel-UDP path byte-identical.
        if (std.posix.getenv("VEX_ENABLE_AFXDP") != null) {
            bindDedicatedArena();
        }

        std.log.info("[TVU] Starting receive loop on port {}", .{self.tvu_port});

        // ── Stage 1 (2026-06-14): spawn the repair/control tile on core 30 ONLY
        // when AF_XDP zero-copy is the active backend (EXACT gate used at the recv
        // zero-copy / verify-handoff path, tvu.zig:373). repair_tile_active is set
        // true ONLY on a successful spawn; on spawn failure it stays false so the
        // three control blocks below run inline (repair never silently dies).
        // When the gate is OFF (kernel-UDP voting node) the tile is never spawned,
        // repair_tile_active stays false, and the inline path is byte-identical.
        if (self.config.enable_af_xdp and self.config.xdp_zero_copy) {
            if (std.Thread.spawn(.{}, repairControlLoop, .{self})) |t| {
                self.repair_tile_thread = t;
                self.repair_tile_active = true;
                std.log.warn("[REPAIR-TILE] spawned repair/control tile (core 30) — repair-control moved off recv core 4", .{});
            } else |err| {
                self.repair_tile_active = false;
                std.log.warn("[REPAIR-TILE] spawn failed ({any}) — repair-control runs INLINE on recv core 4 (no regression)", .{err});
            }
        }

        var loop_count: u64 = 0;
        var last_diagnostic_report: u64 = 0;
        var last_proactive_repair: u64 = 0;
        var last_socket_debug: u64 = 0;
        var proactive_repair_slot: u64 = 0;

        // ── AF_XDP OCCUPANCY INSTRUMENTATION (2026-06-13) ──────────────────
        // 1 Hz summary attributing TVU-loop wall time to phases, to prove/refute
        // the single-thread occupancy stall (checkAndRequestRepairs over up to
        // max_repair_slots in-progress slots monopolizing the loop → recvZeroCopy
        // not called → RX ring overflows → NIC drops turbine). Only emitted when
        // AF_XDP zero-copy is the active backend (else inert / no log spam).
        const afxdp_instrument = std.posix.getenv("VEX_ENABLE_AFXDP") != null;
        var ins_loops: u64 = 0;
        var ins_iter_max_us: u64 = 0;
        var ins_recv_max_us: u64 = 0;
        var ins_zcrecv_max_us: u64 = 0;
        var ins_repdrain_max_us: u64 = 0;
        var ins_checkrep_max_us: u64 = 0;
        var ins_orphan_max_us: u64 = 0;
        var ins_checkrep_sum_us: u64 = 0;
        var ins_last_report_ns: u64 = @intCast(std.time.nanoTimestamp());
        // Phantom-slot discriminator (2026-06-13): emit even on kernel-UDP catch-up
        // (NOT gated by afxdp) so we can compare whether far-future/phantom slot
        // entries are minted on the general path or only the AF_XDP ingest path.
        var inprog_last_ns: u64 = @intCast(std.time.nanoTimestamp());

        while (self.running.load(.acquire)) {
            loop_count += 1;

            const iter_start = std.time.nanoTimestamp();

            // Process incoming packets
            const result = self.processPackets() catch |err| {
                if (loop_count <= 10 or loop_count % 1000 == 0) {
                    std.log.debug("[TVU-ERROR] processPackets failed at loop {d}: {any}\n", .{ loop_count, err });
                }
                continue;
            };

            const pkt_end = std.time.nanoTimestamp();
            const pkt_ms = @as(u64, @intCast(pkt_end - iter_start)) / 1_000_000;

            const iter_end = std.time.nanoTimestamp();
            const iter_ms = @as(u64, @intCast(iter_end - iter_start)) / 1_000_000;

            // Occupancy instrumentation: per-iteration phase timings (μs). The
            // control-phase timings (checkrep/orphan) are filled in below.
            var ins_checkrep_us: u64 = 0;
            var ins_orphan_us: u64 = 0;

            // Log slow iterations
            if (loop_count <= 5 or iter_ms > 1000 or loop_count % 10000 == 0) {
                std.log.debug("[TVU-LOOP] iter={d} pkt={d}ms total={d}ms shreds={d}\n", .{
                    loop_count, pkt_ms, iter_ms, result.shreds_processed,
                });
            }

            // Socket-level debug logging (every 5 seconds)
            if (loop_count > last_socket_debug + 5000) {
                const total_rcvd = self.stats.shreds_received.load(.monotonic);
                const repairs_rcvd = self.stats.repairs_received.load(.monotonic);
                const repairs_sent = self.stats.repairs_sent.load(.monotonic);
                const in_progress = self.shred_assembler.getInProgressSlotCount();

                std.log.debug("[TVU-DEBUG] loop={d} shreds_total={d} repairs_rcvd={d} repairs_sent={d} slots_tracking={d} this_batch={d}\n", .{
                    loop_count,
                    total_rcvd,
                    repairs_rcvd,
                    repairs_sent,
                    in_progress,
                    result.shreds_processed,
                });
                last_socket_debug = loop_count;
            }

            // ✅ COOLING: If we did NO work this iteration, yield the CPU briefly.
            // This prevents "soft lockup" kernel crashes on non-isolated cores.
            // Reduced from 100μs to 10μs — 100μs caused massive packet drops
            // because ~10 packets arrive per 100μs at network rates.
            if (result.shreds_processed == 0) {
                std.Thread.sleep(10 * std.time.ns_per_us);
            }

            // Repair cycle — frequency driven by config.repair_interval_ms (default 50ms)
            const now_ns = @as(u64, @intCast(std.time.nanoTimestamp()));
            const repair_interval_ns = self.config.repair_interval_ms * std.time.ns_per_ms;

            // ── Phantom-slot discriminator (every ~3s, any backend, only when backlog) ──
            if (now_ns > inprog_last_ns + 3 * std.time.ns_per_s) {
                inprog_last_ns = now_ns;
                const ref = self.stats.max_slot_seen.load(.monotonic);
                const st = self.shred_assembler.inProgressStats(ref);
                if (st.count > 50) {
                    std.log.warn("[INPROG-STAT] incomplete={d} min_slot={d} max_slot={d} max_seen(tip)={d} count_above_tip={d} span={d} zc_ver_rej={d}", .{
                        st.count,                                                         st.min_slot,                                    st.max_slot, ref, st.count_above,
                        if (st.max_slot >= st.min_slot) st.max_slot - st.min_slot else 0, self.stats.zc_version_rejects.load(.monotonic),
                    });
                }
            }
            // Stage 1 (2026-06-14): when the core-30 repair tile is active this
            // block runs there instead. When the AF_XDP gate is OFF the tile is
            // never spawned, repair_tile_active is false, and this runs inline
            // byte-identically to today.
            if (!self.repair_tile_active) {
                if (now_ns > self.last_repair_time_ns + repair_interval_ns) {
                    // [REPAIR-INFLIGHT] (gated): kernel-UDP inline driver —
                    // same drain as the tile's Block (1), on the SAME thread
                    // that runs the send + response paths here (recv), under
                    // the 2ms recv budget inside drainExpiredInflight.
                    if (self.repair_inflight_enabled) self.drainExpiredInflight();
                    // Repair up to 500 slots per cycle to cover the full gap
                    const t_cr0 = std.time.nanoTimestamp();
                    self.checkAndRequestRepairs(self.config.max_repair_slots) catch {};
                    ins_checkrep_us = @intCast(@divTrunc(std.time.nanoTimestamp() - t_cr0, 1000));
                    self.last_repair_time_ns = now_ns;

                    // Periodically prune dedup cache (every 5 seconds)
                    if (now_ns > self.last_dedup_cleanup_ns + 5 * std.time.ns_per_s) {
                        self.pruneRepairDedup();
                        self.last_dedup_cleanup_ns = now_ns;
                    }
                }
            }

            // ── ORPHAN REPAIR (2026-05-30) — the FETCH fix for the catch-up
            // stall. Emit Orphan(10) for CHAIN-DEFER "gap-bottom" slots so the
            // 0-shred bridge ancestors between root and tip get DISCOVERED (the
            // peer returns the highest shred of each missing parent → normal
            // window repair fills them → they replay+freeze → checkPendingChain
            // wakes the deferred children). Without this, deferred slots whose
            // parent has no shreds never get the parent fetched → the pending
            // pile grows unbounded → root never advances (the proven stall).
            // Throttled ~500ms; bounded MAX_ORPHANS=5 nearest-root-first; the
            // not-itself-deferred filter (in selectOrphanTargets) prevents a
            // 9000-slot storm. requestOrphan re-samples peers each call =
            // cross-tick rotation.
            {
                const OrphanThrottle = struct {
                    var last_ns: u64 = 0;
                };
                // Stage 1 (2026-06-14): orphan repair runs on the core-30 tile
                // when active; inline (byte-identical) when the AF_XDP gate is OFF.
                // NOTE: the AFXDP-PHASE summary below is INTENTIONALLY left on recv
                // (NET-TILE-PLAN line 83) — it stays OUTSIDE this guard.
                if (!self.repair_tile_active and now_ns > OrphanThrottle.last_ns + 500 * std.time.ns_per_ms) {
                    OrphanThrottle.last_ns = now_ns;
                    const t_orph0 = std.time.nanoTimestamp();
                    if (self.slot_sink) |rs| {
                        const targets: ?[]u64 = rs.collectOrphanTargets(self.allocator, 5) catch null;
                        if (targets) |ts| {
                            defer self.allocator.free(ts);
                            for (ts) |orphan_slot| {
                                self.requestOrphan(orphan_slot) catch {};
                            }
                            if (ts.len > 0 and self.stats.repairs_sent.load(.monotonic) < 400)
                                std.log.warn("[ORPHAN-REPAIR] emitted Orphan(10) for {d} gap-bottom slot(s) (nearest-root)", .{ts.len});
                        }
                    }
                    ins_orphan_us = @intCast(@divTrunc(std.time.nanoTimestamp() - t_orph0, 1000));
                }

                // ── AF_XDP occupancy 1 Hz summary ───────────────────────────────
                if (afxdp_instrument) {
                    ins_loops += 1;
                    if (iter_ms * 1000 > ins_iter_max_us) ins_iter_max_us = iter_ms * 1000;
                    const recv_us = result.recv_ns / 1000;
                    const zcrecv_us = result.zc_recv_only_ns / 1000;
                    const repdrain_us = result.repair_drain_ns / 1000;
                    if (zcrecv_us > ins_zcrecv_max_us) ins_zcrecv_max_us = zcrecv_us;
                    if (recv_us > ins_recv_max_us) ins_recv_max_us = recv_us;
                    if (repdrain_us > ins_repdrain_max_us) ins_repdrain_max_us = repdrain_us;
                    if (ins_checkrep_us > ins_checkrep_max_us) ins_checkrep_max_us = ins_checkrep_us;
                    if (ins_orphan_us > ins_orphan_max_us) ins_orphan_max_us = ins_orphan_us;
                    ins_checkrep_sum_us += ins_checkrep_us;
                    if (now_ns > ins_last_report_ns + std.time.ns_per_s) {
                        var diag: @import("af_xdp/socket.zig").XdpSocket.XdpDiag = .{};
                        // PR0 (2026-07-03, repair catch-up-lag telemetry): kernel-authoritative
                        // XDP_STATISTICS. rx_fill_ring_empty_descs is the ONLY definitive proof of
                        // fill-ring starvation (kernel had a redirected packet but no UMEM frame to
                        // put it in) vs a discovery-bound catch-up lag. These counters were DEFINED
                        // (socket.zig XdpStatistics) but NEVER read — during the 419410933 post-mortem
                        // fill-vs-discovery had to be INFERRED from fill_free/rx_avail. Emitting them
                        // here (~1 getsockopt/sec, read-only, cumulative-since-socket-open) makes the
                        // next incident instantly + authoritatively classifiable. Zero behavior change:
                        // only runs inside the existing VEX_ENABLE_AFXDP instrument block.
                        var kstats = std.mem.zeroes(@import("af_xdp/socket.zig").XdpStatistics);
                        if (self.shred_io) |io| {
                            if (io.getXdpSocket()) |xdp| {
                                diag = xdp.diag();
                                kstats = xdp.getStats() catch kstats;
                            }
                        }
                        const in_prog = self.shred_assembler.getInProgressSlotCount();
                        const tlf = if (self.verify_tile_instance) |vt| vt.queue.trylock_fail.load(.monotonic) else 0;
                        const stg_depth = self.staging_head -% self.staging_tail;
                        // Option B (2026-06-14) discriminator: zc_overrun = frames dropped
                        // because ALL verify rings were full (genuine verify-parallelism
                        // overrun). ring_depth_max = deepest single-ring backlog right now.
                        // If zc_overrun stays ≈0 yet AF_XDP still wedges (bridge slots
                        // missing, root stuck) → the wedge is the repair path (NEXT-2), NOT
                        // the verify handoff. High ring_depth_max during catch-up → a worker
                        // is descheduled (core-map collision) OR a verify-count limit.
                        var zc_ovr: u64 = 0;
                        var ring_depth_max: u32 = 0;
                        // POSITIVE throughput signal (advisor): cumulative frames pushed/
                        // popped across all rings. zc_overrun≈0 + ring_depth_max≈0 is
                        // AMBIGUOUS — it is equally the signature of "rings perfectly
                        // drained" AND "rings never carried any traffic" (silent kernel-UDP
                        // fallback, or the kernel socket carrying shreds). ring_pushed
                        // CLIMBING at ~turbine rate is the only proof Option B actually ran.
                        var ring_pushed: u64 = 0;
                        var ring_popped: u64 = 0;
                        if (self.verify_tile_instance) |vt| {
                            zc_ovr = vt.zc_overrun.load(.monotonic);
                            if (vt.zc_rings) |rings| {
                                for (rings) |r| {
                                    const d = r.len();
                                    if (d > ring_depth_max) ring_depth_max = d;
                                    ring_pushed += r.pushed.load(.monotonic);
                                    ring_popped += r.popped.load(.monotonic);
                                }
                            }
                        }
                        std.log.warn("[AFXDP-PHASE] loops/s={d} iter_max={d}ms | recv_max={d}us zcrecv_max={d}us repdrain_max={d}us checkrep_max={d}ms(sum={d}ms) orphan_max={d}ms | held={d} free_depth={d} fill_free={d} rx_avail={d} spill={d} inprog_slots={d} | trylock_fail={d} stg_depth={d} stg_max={d} stg_overrun={d} | zc_pushed={d} zc_popped={d} zc_overrun={d} ring_depth_max={d} | krx_drop={d} krx_ringfull={d} kfill_empty={d}", .{
                            ins_loops,
                            ins_iter_max_us / 1000,
                            ins_recv_max_us,
                            ins_zcrecv_max_us,
                            ins_repdrain_max_us,
                            ins_checkrep_max_us / 1000,
                            ins_checkrep_sum_us / 1000,
                            ins_orphan_max_us / 1000,
                            diag.frames_held,
                            diag.free_depth,
                            diag.fill_free,
                            diag.rx_avail,
                            diag.spill_events,
                            in_prog,
                            tlf,
                            stg_depth,
                            self.staging_depth_max,
                            self.staging_overrun,
                            ring_pushed,
                            ring_popped,
                            zc_ovr,
                            ring_depth_max,
                            kstats.rx_dropped,
                            kstats.rx_ring_full,
                            kstats.rx_fill_ring_empty_descs,
                        });
                        // FIX 2026-07-07 (carrier 420258409 follow-up): free_depth==0 means the
                        // UMEM recycle reservoir is exhausted — the exact precondition under which
                        // the NIC can recycle a frame the verify worker is still processing
                        // ([FRAME-OVERWRITE]/[FRAME-DROP] in shred.zig). This is a DISTINCT,
                        // easy-to-grep low-water alarm (pure diagnostic, no behavior change) rather
                        // than requiring an operator to eyeball the dense line above.
                        //
                        // RATE-LIMIT (2026-07-07, same-day follow-up): this block already only
                        // runs once/sec (the outer 1Hz gate above), but a SUSTAINED spiral (the
                        // free_depth=0 stretch that produced 259 [FRAME-DROP] in 20min) still means
                        // one line per second indefinitely — thousands of lines over a multi-hour
                        // outage. Emit first occurrence + every 1000th + a one-shot "recovered" line
                        // instead (same shape as the [ZC-VERSION-REJECT]/[RX-SHED] counters above).
                        if (diag.free_depth == 0) {
                            self.pool_low_streak += 1;
                            if (self.pool_low_streak == 1 or self.pool_low_streak % 1000 == 0) {
                                std.log.warn("[AFXDP-POOL-LOW] #{d} free_depth=0 (UMEM recycle reservoir exhausted) fill_free={d} frames_held={d} rx_avail={d} — frame-overwrite/drop race is now possible (backpressure gate should now be shedding, see [RX-SHED])", .{
                                    self.pool_low_streak, diag.fill_free, diag.frames_held, diag.rx_avail,
                                });
                            }
                        } else if (self.pool_low_streak > 0) {
                            std.log.warn("[AFXDP-POOL-LOW-RECOVERED] free_depth={d} after {d} consecutive 1Hz samples at 0", .{
                                diag.free_depth, self.pool_low_streak,
                            });
                            self.pool_low_streak = 0;
                        }
                        ins_loops = 0;
                        ins_iter_max_us = 0;
                        ins_recv_max_us = 0;
                        ins_zcrecv_max_us = 0;
                        ins_repdrain_max_us = 0;
                        ins_checkrep_max_us = 0;
                        ins_orphan_max_us = 0;
                        ins_checkrep_sum_us = 0;
                        ins_last_report_ns = now_ns;
                    }
                }
            }

            // PROACTIVE REPAIR — lightweight discovery of NEW slots.
            // Only probe 5 slots ahead every 10 seconds with just indices 0-7.
            // Stage 1 (2026-06-14): runs on the core-30 tile when active; inline
            // (byte-identical) when the AF_XDP gate is OFF.
            if (!self.repair_tile_active and loop_count > last_proactive_repair + 10000) { // Every ~10 seconds
                const max_seen = self.stats.max_slot_seen.load(.monotonic);
                if (max_seen > 0 and max_seen < 1_000_000_000) {
                    var bootstrap_indices: [8]u32 = undefined;
                    for (&bootstrap_indices, 0..) |*idx, i| {
                        idx.* = @intCast(i);
                    }

                    // Probe 5 slots ahead — just enough to discover new slots
                    var advance: u64 = 1;
                    while (advance <= 5) : (advance += 1) {
                        const target_slot = max_seen +| advance;
                        if (target_slot != proactive_repair_slot) {
                            self.requestRepairs(target_slot, &bootstrap_indices) catch |err| {
                                std.log.debug("[TVU proactive-repair] requestRepairs err: {any}\n", .{err});
                            };
                        }
                    }
                    proactive_repair_slot = max_seen + 1;

                    // Also evict OLD stale slots — but ONLY in normal mode.
                    // During catch-up, the time-based sweeper handles cleanup.
                    //
                    // d27v (2026-05-11): use distance from root_bank, not from
                    // highest_completed_slot, to detect catchup mode.
                    // highest_completed_slot tracks the MAXIMUM slot whose
                    // shred-assembly finished — during catchup that hits the
                    // cluster tip quickly (latest slots arrive fast via
                    // turbine) while root_bank stays at snapshot+N. So the old
                    // `max_seen - highest_completed_slot <= 5000` test reads
                    // as "caught up" the moment ANY tip slot completes, then
                    // evicts in-progress near-root slots that are >150 behind
                    // max_seen → near-root slots get killed before WindowIndex
                    // fill-in finishes. Same class as d24 slot-assassination,
                    // different code path.
                    var real_gap: u64 = std.math.maxInt(u64);
                    if (self.slot_sink) |rs| {
                        if (rs.rootBank()) |rb| {
                            real_gap = if (max_seen > rb.slot) max_seen - rb.slot else 0;
                        }
                    }
                    if (real_gap <= 50) {
                        const stale_slots = self.shred_assembler.getInProgressSlots() catch &[_]u64{};
                        defer self.allocator.free(stale_slots);
                        for (stale_slots) |stale_slot| {
                            if (stale_slot + STALE_SLOT_THRESHOLD < max_seen) {
                                self.shred_assembler.removeSlot(stale_slot);
                            }
                        }
                    }

                    if (@mod(loop_count, 30000) == 0) {
                        const in_progress = self.shred_assembler.getInProgressSlotCount();
                        std.log.debug("[TVU-ADVANCE] max_seen={d} slots_tracking={d} proactive_slot={d}\\n", .{
                            max_seen, in_progress, proactive_repair_slot,
                        });
                    }
                }
                last_proactive_repair = loop_count;
            }

            // Update Turbine tree periodically (every 30 seconds, time-based)
            if (now_ns > self.last_turbine_update_ns + 30 * std.time.ns_per_s) {
                self.updateTurbineTree();
                self.last_turbine_update_ns = now_ns;
            }

            // Print comprehensive diagnostics every 30 seconds
            if (loop_count > last_diagnostic_report + 30000) {
                self.printComprehensiveDiagnostics();
                last_diagnostic_report = loop_count;
            }

            // Comprehensive diagnostics every 60 seconds (time-based)
            if (now_ns > self.last_diag_ns + 60 * std.time.ns_per_s) {
                const total_shreds = self.stats.shreds_received.load(.monotonic);
                const total_invalid = self.stats.shreds_invalid.load(.monotonic);
                const total_repairs_rcvd = self.stats.repairs_received.load(.monotonic);
                const total_repairs_sent = self.stats.repairs_sent.load(.monotonic);
                const completed_slots = self.shred_assembler.highest_completed_slot.load(.monotonic);
                const in_progress = self.shred_assembler.getInProgressSlotCount();
                const max_seen = self.stats.max_slot_seen.load(.monotonic);
                const pending = self.pending_slots.items.len;
                const uptime_s = (now_ns - self.start_time_ns) / std.time.ns_per_s;

                std.log.debug(
                    \\
                    \\╔══════════════════════════════════════════════════════╗
                    \\║  VEX-FD DIAGNOSTICS (uptime: {d}s)
                    \\║  Shreds:     {d} received, {d} invalid
                    \\║  Slots:      {d} completed, {d} in-progress, {d} pending replay
                    \\║  Network:    max_slot={d}, highest_completed={d}
                    \\║  Repair:     {d} sent, {d} received
                    \\║  Loop:       iter={d}
                    \\╚══════════════════════════════════════════════════════╝
                    \\
                , .{
                    uptime_s,
                    total_shreds,
                    total_invalid,
                    completed_slots,
                    in_progress,
                    pending,
                    max_seen,
                    completed_slots,
                    total_repairs_sent,
                    total_repairs_rcvd,
                    loop_count,
                });
                self.last_diag_ns = now_ns;
            }

            // Only sleep if we processed zero shreds this iteration.
            // With 1.5M kernel drops, every microsecond counts.
            // The 10μs cooling sleep at line 2211 already handles idle case.
        }

        // Stage 1 (2026-06-14): join the repair/control tile. self.running is now
        // false (the loop above exited on it), and the tile checks the same flag
        // with .acquire, so it drains its current iteration and returns.
        if (self.repair_tile_thread) |t| {
            t.join();
            self.repair_tile_thread = null;
            self.repair_tile_active = false;
        }

        std.log.info("[TVU] Receive loop stopped", .{});
    }

    /// Get current network slot from gossip contacts' slot values
    /// Falls back to 0 if no gossip info available
    fn getNetworkSlot(self: *Self) u64 {
        const gs = self.gossip_service orelse return 0;

        // Count peers with matching shred version
        var matching_peers: usize = 0;
        gs.table.contacts_rw.lockShared();
        defer gs.table.contacts_rw.unlockShared();
        var iter = gs.table.contacts.iterator();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr.*;
            // Check if peer has advertised matching shred_version
            if (peer.shred_version == self.config.shred_version or peer.shred_version == 0) {
                matching_peers += 1;
            }
        }

        // For proactive repair, we need to estimate current network slot
        // 1. Use the maximum slot seen from shreds if available
        const max_seen = self.stats.max_slot_seen.load(.monotonic);
        if (max_seen > 300_000_000) return max_seen + 1;

        // 2. Fallback: use current timestamp divided by slot time (~400ms)
        // starting from a known recent testnet slot (Feb 2026: ~386,000,000)
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        const approx_slot = now_ms / 400;

        // Only trigger proactive repair if we have enough gossip peers
        if (matching_peers > 50) {
            // Testnet is currently around slot 386,000,000+
            return 386_000_000 + (approx_slot % 200_000);
        }

        return 0;
    }

    /// Maximum age (in slots) before a tracked slot is considered stale and evicted.
    /// Only used during NORMAL operation (gap < CATCHUP_MODE_THRESHOLD).
    /// During catch-up, distance-based eviction is bypassed entirely to let
    /// repair finish assembling slots. The time-based sweeper handles cleanup.
    const STALE_SLOT_THRESHOLD: u64 = 150;

    /// When our gap to network head exceeds this, we are in deep catch-up mode
    /// and distance-based eviction is disabled to prevent slot assassination.
    const CATCHUP_MODE_THRESHOLD: u64 = 5000;

    /// Check for missing shreds and request repairs
    /// IMPROVED: Prioritizes slots with last_in_slot detected and requests in batches
    fn checkAndRequestRepairs(self: *Self, max_slots_to_repair: usize) !void {
        // Check each slot in assembler for gaps
        const slots = self.shred_assembler.getInProgressSlots() catch return;
        defer self.allocator.free(slots);

        // RECV-THREAD TIME BUDGET (2026-06-14): one wall-clock deadline for the
        // whole cycle — the catch-up seed burst AND the per-slot repair loop must
        // both honor it so the recv thread is never blocked long enough to starve
        // the XSK fill ring (turbine drop → freeze-tip wedge). See REPAIR_RECV_BUDGET_NS.
        // FIX A (2026-06-14, diagnosis wn5fqhilj): on the dedicated core-30 repair tile
        // the recv-fill-ring constraint does NOT apply (separate thread/core), so use
        // the generous tile budget — the 2ms cap throttled catch-up to ~10 req/cycle.
        // The inline path (recv thread, kernel-UDP / AF_XDP-off) keeps the 2ms cap.
        const budget_ns: i128 = if (self.repair_tile_active) REPAIR_TILE_BUDGET_NS else REPAIR_RECV_BUDGET_NS;
        const cycle_deadline: i128 = std.time.nanoTimestamp() + budget_ns;

        // d27l (2026-05-11): periodic catchup-seed re-fire. The seed is
        // throttled to once per 30s and self-terminates once root_bank
        // catches past turbine_slot0. This is what makes the burst pattern
        // actually work — gossip grows from ~70 peers at first-turbine-shred
        // to 500+ over the next 60-90s. Calling here from the existing
        // repair loop is the cleanest place to drive periodic re-fires
        // without spawning another thread.
        const t0_unset: u64 = std.math.maxInt(u64);
        const t0 = self.turbine_slot0.load(.acquire);
        // Network head — the live cluster frontier observed off the wire.
        const network_head = self.stats.max_slot_seen.load(.monotonic);
        if (t0 != t0_unset) {
            // FIX #2 (2026-06-14, AF_XDP bridge wedge): seed up to the LIVE
            // frontier, not the stale turbine_slot0. turbine_slot0 is captured
            // ONCE at first-turbine-shred (tvu.zig:1605 cmpxchg from UNSET) and
            // NEVER advances. Seeding only (consensus_root, turbine_slot0] left
            // the ~800-slot span (turbine_slot0, live_tip] — the "turbine
            // territory" bridge — requested by nothing. Under recv stalls those
            // turbine shreds drop → holes → pending_chain grows unbounded →
            // chain-defer wedge (observed: consensus_root frozen, gap climbing
            // 546→791, pending_chain 313→563). seedCatchupRepairs already
            // self-terminates once db.rooted_slot >= turbine_slot0 per slot, and
            // its HighestWindowIndex bursts are de-duped against in-progress
            // slots, so extending the upper bound to network_head is safe and
            // is what actually bridges the gap to the live tip.
            const frontier = @max(t0, network_head);
            self.seedCatchupRepairs(frontier, cycle_deadline);
        }

        // NOTE: Distance-based eviction (REPAIR-PRUNE) has been REMOVED.
        // It was the root cause of slot assassination during catch-up: slots
        // >150 behind network_head were deleted before repair could complete them.
        // The time-based sweeper (5-minute timeout for repair slots) handles
        // cleanup of truly dead slots without killing active repair work.

        // d27x (2026-05-11): @prov:tvu.repair-priority-cap — canonical
        // prioritization caps repair requests at MAX_REPAIR_LENGTH=512
        // per iteration and traverses the rooted tree from root_bank,
        // sorting children by stake weight — closest-to-root slots get
        // the budget first. Vexor was iterating getInProgressSlots() in
        // HashMap bucket order with NO total cap, so 495 in-progress
        // slots competed equally for repair bandwidth and near-root
        // slots got starved (NEAR-ROOT-INSERT showed 320 inserts on one
        // slot, 1 each on thirteen others).
        //
        // Vexor port: sort slots ascending (closest to root_bank first
        // since chain extends slot-by-slot from root), cap TOTAL repair
        // requests per iteration at AGAVE_MAX_REPAIR_LENGTH so the
        // budget lands on the slots that actually need to freeze next.
        //
        // We don't have stake-weighted fork-choice tree here (Vexor's
        // chain-defer is a flat HashMap), so slot-number ascending IS
        // the right proximity proxy: lowest slots are closest to
        // root_bank.slot in chain order.
        //
        // 2026-05-27 FIX #48.3: RESTORED to Agave canonical 512 after
        // Ballet ed25519 SIGN wired (commit bfd08c8, Task #51). Ballet
        // AVX-512 ed25519 gives ~5× throughput (~50-75K signs/sec) vs
        // Zig stdlib (~10-15K signs/sec). 512/iter × 20Hz = 10240 signs/sec
        // is well within Ballet's budget, removing the prior CPU saturation
        // that forced HOTFIX #48.2 to drop to 200. @prov:tvu.repair-priority-cap
        // MAX_REPAIR_LENGTH = 512.
        const AGAVE_MAX_REPAIR_LENGTH: usize = 512;
        // Sort in-place. `slots` is owned by us (toOwnedSlice from
        // getInProgressSlots), so mutating it is safe.
        std.mem.sort(u64, slots, {}, std.sort.asc(u64));

        // PR-5r (2026-05-19): pre-root slot filter — prevents the 512-request
        // AGAVE_MAX_REPAIR_LENGTH budget from being consumed by already-rooted
        // slots below the consensus root. On cold-boot the assembler accumulates
        // gossip- and turbine-discovered shreds for slots well before the snapshot
        // anchor; because the ascending sort above places lowest slots first,
        // those pre-root entries exhaust the budget before the iteration reaches
        // near-root gap slots that MUST be filled for the chain to extend.
        // Symptom of the bug: validator boots, Assembler receives at-tip
        // shreds, but slot_queue stays empty (pending_chain_count climbs but
        // no slots ever freeze) because near-root gap slots never receive
        // repair requests. Fix: cache root once and skip any slot <= root.
        // Pre-root slots stay in the assembler (cleaned by time-based sweep)
        // but no longer compete for repair budget.
        //
        // FIX #114 (2026-05-30): gate on the CONSENSUS root (`accounts_db.rooted_slot`
        // — the monotonic tower/supermajority root), NOT `root_bank.slot` (the
        // LAST-FROZEN bank, which is non-monotonic and was observed live as a
        // MINORITY fork slot, e.g. 412043126, sitting ~455 slots ABOVE the consensus
        // root 412042671). Keying on root_bank made this filter over-skip the range
        // (consensus_root, root_bank] — which contains the canonical BRIDGE slots
        // (e.g. 412043124/125, parents of the wedge tip) that MUST be window-repaired
        // to extend the chain. They were dropped from repair entirely → never
        // completed → frontier wedged at the prior canonical slot while `head` ran
        // 12k slots ahead. This is the SAME root_bank-vs-consensus_root confusion
        // FIX #112 fixed for the pending-chain GC / fast-wake (replay_stage.zig:1730
        // etc.) — here in the 4th site (the repair budget filter). `<=` is retained:
        // a slot AT the consensus root is already rooted/frozen and needs no repair.
        // If accounts_db is somehow unset (only at very early bootstrap, before
        // replay), fall through to 0 → filter disabled (repair everything; safe, the
        // 512 budget cap still bounds it). We deliberately NO LONGER fall back to
        // root_bank.slot — that path is exactly the bug.
        const root_slot_for_filter: u64 = blk: {
            if (self.slot_sink) |rs| {
                if (rs.accountsDb()) |db| break :blk db.rooted_slot;
            }
            break :blk 0;
        };

        // SLOT-AWARE REPAIR (2026-06-14): advance + prune the ClusterSlots index at
        // the SAME consensus-root cadence as the repair budget filter. setRoot is
        // monotonic and bounds the index to (root, root+SLOT_WINDOW]. Called here
        // (outside any repair_peers_mutex hold) so we never hold cluster_slots.mutex
        // across getRepairPeers — preserving the lock order (repair_peers ->
        // cluster_slots, writer/pruner take cluster_slots alone).
        if (root_slot_for_filter > 0) self.cluster_slots.setRoot(root_slot_for_filter);

        var slots_repaired: usize = 0;
        var total_repair_requests: usize = 0;
        var pre_root_skipped: usize = 0;
        for (slots) |slot| {
            if (slots_repaired >= max_slots_to_repair) break;
            if (total_repair_requests >= AGAVE_MAX_REPAIR_LENGTH) break;
            // RECV-THREAD BUDGET (2026-06-14): stop issuing per-slot repair the
            // moment the cycle deadline passes — the rest is handled next cycle
            // (50ms). Keeps the recv thread free to drain turbine (see cycle_deadline).
            if (std.time.nanoTimestamp() >= cycle_deadline) break;

            if (root_slot_for_filter > 0 and slot <= root_slot_for_filter) {
                pre_root_skipped += 1;
                continue;
            }

            const slot_info = self.shred_assembler.getSlotInfo(slot) catch continue;

            // BRIDGE-DIAG (2026-06-14): the LOWEST actionable in-progress slot is
            // the one whose completion advances the freeze-tip. When the validator
            // wedges with freeze stuck and this slot in-progress-but-never-complete,
            // we must see WHY: knows_last_shred (can we even recognise completion?),
            // how many shreds we have vs need, and the highest index received. The
            // [FEC-CHAINED-SKIP] log (fec_resolver) shows separately whether this
            // slot's chained FEC sets are having RS recovery skipped (one unservable
            // data shred + skipped recovery = permanent single-slot wedge). slots[]
            // is sorted ascending and pre-root slots already `continue`d above, so
            // the first slot to reach here is the lowest actionable one.
            if (slots_repaired == 0) {
                const BridgeDiag = struct {
                    var last_ns: i128 = 0;
                };
                const dnow = std.time.nanoTimestamp();
                if (dnow - BridgeDiag.last_ns > std.time.ns_per_s) {
                    BridgeDiag.last_ns = dnow;
                    const highest = self.shred_assembler.getHighestIndex(slot) catch 0;
                    const needed: i64 = if (slot_info.knows_last_shred) @as(i64, @intCast(slot_info.last_shred_index)) + 1 else -1;
                    const have: i64 = @intCast(slot_info.unique_count);
                    std.log.warn("[BRIDGE-DIAG] lowest_inprog_slot={d} knows_last={} last_idx={d} have={d} need={d} highest_recv={d} missing={d}", .{
                        slot,
                        slot_info.knows_last_shred,
                        slot_info.last_shred_index,
                        have,
                        needed,
                        highest,
                        if (needed > 0) needed - have else -1,
                    });
                }

                // FIX B2 (2026-06-14, AF_XDP catch-up wedge diagnostics — LOG ONLY):
                // track the LOWEST actionable in-progress slot as a single bounded
                // "stuck slot". When it has a SMALL missing set (<=4) and has been
                // the lowest slot for > ~10s, emit a throttled [REPAIR-STUCK] warn
                // showing how many repair requests we've sent for it and how many
                // repair-shred RESPONSES arrived FOR that exact slot — answering
                // "do peers answer for that specific stuck index?". The acute wedge
                // is have=N/need=N+1 (a single interior data shred) requested every
                // cycle to hundreds of peers but never landing, with no warn signal.
                // Reset the timer/counters whenever the lowest-slot IDENTITY changes
                // (so the >10s clock measures THIS slot's stuck duration). Zero
                // control-flow / validation change.
                {
                    const missing_now: i64 = if (slot_info.knows_last_shred)
                        (@as(i64, @intCast(slot_info.last_shred_index)) + 1) - @as(i64, @intCast(slot_info.unique_count))
                    else
                        -1;
                    const prev_stuck = self.stuck_slot.load(.acquire);
                    const tnow = std.time.nanoTimestamp();
                    if (prev_stuck != slot) {
                        // Lowest-slot identity changed — (re)start tracking this slot.
                        self.stuck_slot.store(slot, .release);
                        self.stuck_slot_since_ns.store(tnow, .release);
                        self.stuck_slot_requests.store(0, .release);
                        self.stuck_slot_resp_count.store(0, .release);
                        self.stuck_slot_last_warn_ns.store(0, .release);
                        // FIX #3: identity changed → reset escalation arm + HWI throttle
                        // + progress watermark (seed with this slot's current count/now).
                        self.stuck_slot_last_hwi_rederive_ns.store(0, .release);
                        self.stuck_slot_failstop_armed_ns.store(0, .release);
                        self.stuck_slot_progress_count.store(slot_info.unique_count, .release);
                        self.stuck_slot_progress_ns.store(tnow, .release);
                    } else {
                        // FIX #3: update the progress watermark — if this slot has gained
                        // any new shreds since last cycle, it is making forward progress
                        // (NOT wedged); record the higher count + advance the timestamp so
                        // the no-progress window measures genuine stall, not gap-fill on a
                        // slot that's still slowly completing.
                        if (slot_info.unique_count > self.stuck_slot_progress_count.load(.acquire)) {
                            self.stuck_slot_progress_count.store(slot_info.unique_count, .release);
                            self.stuck_slot_progress_ns.store(tnow, .release);
                        }
                        // prev_stuck == slot: same lowest in-progress slot persists.
                        const since = self.stuck_slot_since_ns.load(.acquire);
                        // LOG-ONLY [REPAIR-STUCK] warn for the small-missing (knows_last)
                        // case — the have=N/need=N+1 acute wedge B2 was built to surface.
                        if (missing_now > 0 and missing_now <= 4 and since != 0 and (tnow - since) > 10 * std.time.ns_per_s) {
                            const last_warn = self.stuck_slot_last_warn_ns.load(.acquire);
                            if (tnow - last_warn > std.time.ns_per_s) {
                                self.stuck_slot_last_warn_ns.store(tnow, .release);
                                const miss_idx = self.shred_assembler.getMissingIndices(slot) catch &[_]u32{};
                                defer if (miss_idx.len > 0) self.allocator.free(miss_idx);
                                std.log.warn("[REPAIR-STUCK] slot={d} missing={any} requests_sent={d} resp_for_slot={d} stuck_ms={d}", .{
                                    slot,
                                    miss_idx[0..@min(miss_idx.len, 4)],
                                    self.stuck_slot_requests.load(.acquire),
                                    self.stuck_slot_resp_count.load(.acquire),
                                    @divTrunc(tnow - since, std.time.ns_per_ms),
                                });
                            }
                        }

                        // FIX #3 (2026-06-14): bounded-retry → restart FLOOR.
                        // CRITICAL: evaluated for the tracked stuck slot REGARDLESS of
                        // `missing_now`, so it covers BOTH phantom shapes:
                        //   - knows_last=TRUE, missing=N+1 interior index nobody has
                        //     (the observed have=N/need=N+1 wedge), AND
                        //   - knows_last=FALSE (missing_now == -1): the LAST_IN_SLOT shred
                        //     was DROPPED/withheld at ZC ingest (the FEC-boundary guard /
                        //     ZC is_last defect the task describes) → last_index never set
                        //     → repair sits in CASE 2 firing HWI into the void forever.
                        // An earlier draft nested this inside `missing_now <= 4`, which
                        // requires knows_last=TRUE and silently EXCLUDED the dropped-LAST
                        // phantom — the task's primary mechanism. Now gated only on the
                        // PHANTOM SIGNATURE (NOT pure wall-clock, which would trip on
                        // slow-but-legitimate cold-boot catch-up): same slot stuck for a
                        // conservative window AND many requests issued for it AND peers
                        // answer for it ~never (resp_for_slot ≈ 0). A node that's merely
                        // behind gets responses, so resp_count climbs and we never escalate.
                        if (since != 0) {
                            const reqs = self.stuck_slot_requests.load(.acquire);
                            const resps = self.stuck_slot_resp_count.load(.acquire);
                            const stuck_ns = tnow - since;
                            // Thresholds (conservative — never trip during normal catch-up):
                            //  - STUCK_ESCALATE_NS: 2 min before ANY escalation.
                            //  - STUCK_FAILSTOP_NS: 5 min before the fail-stop floor.
                            //  - need many requests issued and essentially no answers.
                            const STUCK_ESCALATE_NS: i128 = 2 * 60 * @as(i128, std.time.ns_per_s);
                            const STUCK_FAILSTOP_NS: i128 = 5 * 60 * @as(i128, std.time.ns_per_s);
                            const MIN_REQUESTS_FOR_ESCALATE: u64 = 200;
                            const MAX_RESP_FOR_PHANTOM: u64 = 2; // ~0 answers for this slot
                            // PROGRESS-based discriminator (robust to mixed wedges): the
                            // slot has gained NO new shreds for at least the escalate
                            // window. resp_count<=2 is kept as an additional (cumulative)
                            // signal, but no-progress is the authoritative wedge proof —
                            // it cannot be inflated by historical gap-fill. Require BOTH
                            // many requests AND (no progress OR ~0 responses). A
                            // slow-but-filling slot trips NEITHER (it advances unique_count,
                            // refreshing progress_ns, AND its identity changes once it
                            // freezes → full reset). A healthy/advancing lowest slot never
                            // stays the lowest for minutes (identity changes → since reset).
                            const no_progress_ns = tnow - self.stuck_slot_progress_ns.load(.acquire);
                            const no_progress = no_progress_ns > STUCK_ESCALATE_NS;
                            // Pure, KAT-tested discriminator (repair_escalate.zig):
                            // byte-identical to the prior inline expression. Keeps
                            // the wedge-vs-slow-catch-up decision unit-proven, not
                            // reasoned-correct in this socket-heavy file.
                            const phantom_signature = repair_escalate.phantomSignature(
                                reqs,
                                no_progress,
                                resps,
                                MIN_REQUESTS_FOR_ESCALATE,
                                MAX_RESP_FOR_PHANTOM,
                            );

                            // ── GATE-ONLY error-injection hook (comptime-eliminated unless -Dgate_hooks=true) ──
                            // ZERO production footprint: when build_options.gate_hooks is comptime-FALSE the
                            // whole `if (comptime …) blk:` is pruned, `inject_hit` folds to a comptime `false`,
                            // and both `escalate` (below) and the fail-stop guard collapse byte-identically to
                            // the un-hooked expressions (`x or false` == `x`). It compiles NO env read, NO
                            // struct, NO log in a normal build. When a GATE build is active AND the env
                            // VEX_INJECT_WEDGE_SLOT=S is set, this FORCES the wedge for the tracked stuck
                            // lowest-in-progress slot the first cycle it IS S and S is a phantom
                            // (knows_last_shred == false) — bypassing ONLY the 2-min escalate timer, the 5-min
                            // fail-stop timer, and the phantom-signature detector. Nothing else changes: the
                            // SAME real skip-abandoned oracle check → HWI-rederive → fail-stop code below then
                            // runs for S, so the offline-replay gate exercises the actual fix logic. This
                            // reproduces the flaky-live 5-min repair-wedge deterministically in seconds. The
                            // env is read ONCE + cached (std.once), same pattern as repairSkipAbandonedEnabled.
                            const inject_hit: bool = if (comptime build_options.gate_hooks) blk: {
                                const Inject = struct {
                                    var init = std.once(resolve);
                                    var wedge_slot: u64 = 0;
                                    var logged: bool = false;
                                    fn resolve() void {
                                        if (std.posix.getenv("VEX_INJECT_WEDGE_SLOT")) |v| {
                                            wedge_slot = std.fmt.parseInt(u64, std.mem.trim(u8, v, " \t\r\n"), 10) catch 0;
                                        }
                                    }
                                };
                                Inject.init.call();
                                if (Inject.wedge_slot != 0 and slot == Inject.wedge_slot and !slot_info.knows_last_shred) {
                                    if (!Inject.logged) {
                                        Inject.logged = true;
                                        std.log.warn("[INJECT-WEDGE] slot={d} forcing escalate (gate build, VEX_INJECT_WEDGE_SLOT) — bypassing escalate/fail-stop timers + phantom detector; real skip-abandoned/HWI/fail-stop path runs unchanged", .{slot});
                                    }
                                    break :blk true;
                                }
                                break :blk false;
                            } else false;

                            const escalate = (stuck_ns > STUCK_ESCALATE_NS and phantom_signature) or inject_hit;
                            if (escalate) {
                                // ── VEX_REPAIR_SKIP_ABANDONED (default OFF): oracle-guarded INVERSE-SKIP ──
                                // BEFORE the HWI-rederive / fail-stop, ask the CLUSTER ORACLE whether this
                                // stuck lowest-in-progress BRIDGE slot X is a slot the cluster genuinely
                                // SKIPPED (partial shreds, is_full=false; the canonical chain routes AROUND
                                // it, e.g. …195 → …197 with 197.parent==195, bypassing 196). If confirmed,
                                // ABANDON X in-process — drop it from the in-progress + repair set so it is
                                // no longer the mandatory contiguous bridge — instead of fail-stopping.
                                // This is the Agave RepairWeight::set_root (repair_weight.rs:385) /
                                // BankForks::prune_non_rooted (bank_forks.rs:659) analog, fired off the
                                // CLUSTER oracle because Vexor's OWN root is the wedged thing (we cannot ask
                                // our own root; we ask the cluster's, which is Blockstore::is_skipped's
                                // "lowest_root < slot < max_root AND no root entry", blockstore.rs:4820).
                                // It NEVER trusts raw parent_offset — the May-2026 Phase-J variant did and
                                // false-positived on FORKED validators lying about parent_offset, killing
                                // canonical slots → bank_hash divergence. The oracle here is the cluster's
                                // getBlocks(X-16, X+16) PRODUCED-slot list (Agave RPC = the HISTORICAL
                                // is_skipped analog, covering slots FAR behind our wedged tip — where the
                                // cluster's 512-slot SlotHashes window does NOT reach, which is why the
                                // earlier SlotHashes probe never fired on a real catch-up wedge). The pure,
                                // KAT-tested discriminator repair_escalate.clusterConfirmedSkip requires the
                                // getBlocks query to SUCCEED and to BOUND X with a produced slot on BOTH
                                // sides (coverage proof) while X itself is ABSENT — that IS is_skipped, and a
                                // forked validator's lie can never enter getBlocks (it returns only the
                                // cluster's rooted/confirmed slots). Default OFF; armed only after an
                                // offline-replay gate (VEX_SKIP_CANON_FILE feeds a oracle-node-derived produced
                                // list so a 12h-old wedge slot, absent from live RPC retention, still gates).
                                if (repairSkipAbandonedEnabled()) {
                                    if (self.slot_sink) |rs| {
                                        // getBlocks (is_skipped) NEIGHBORHOOD of the stuck slot X.
                                        const SKIP_SPAN: u64 = 16;
                                        const lo = if (slot > SKIP_SPAN) slot - SKIP_SPAN else 0;
                                        const hi = slot +| SKIP_SPAN;
                                        const now_ns = @as(u64, @intCast(std.time.nanoTimestamp()));
                                        // THROTTLE (fixes the old per-50ms getParentSlot spam): query
                                        // getBlocks for [X-16, X+16] AT MOST once per 30s per stuck slot X,
                                        // caching the produced list. A new stuck slot forces a fresh query;
                                        // otherwise we reuse the cache for 30s. A FAILED query also updates
                                        // the throttle stamps, so a persistent RPC failure does NOT re-fire
                                        // every cycle.
                                        const SKIP_STALE_NS: u64 = 30 * std.time.ns_per_s;
                                        const need_query = (self.skip_canon_slot != slot) or
                                            (now_ns -| self.skip_canon_query_ns >= SKIP_STALE_NS);
                                        if (need_query) {
                                            if (self.skip_canon_produced) |old| self.allocator.free(old);
                                            // fetchProducedSlots BLOCKS (fork-exec `curl -m 3`, ≤3s) on THIS
                                            // thread — the core-30 repair tile under AF_XDP (the live config,
                                            // NOT the recv/fill-ring thread) or, on the kernel-UDP fallback,
                                            // the recv thread. Acceptable: it fires at most once/30s and only
                                            // while the gate is ON and the node is ALREADY wedged on this
                                            // exact slot (already stalled). Self-contained curl → no lock.
                                            self.skip_canon_produced = rs.fetchProducedSlots(lo, hi);
                                            self.skip_canon_slot = slot;
                                            self.skip_canon_query_ns = now_ns;
                                        }
                                        // Firewall inputs from the produced list. `query_ok` == the getBlocks
                                        // query SUCCEEDED (non-null); a null (RPC failure / range not in
                                        // retention) FAILS CLOSED at clause 1. lower/higher are the produced
                                        // slots that BOUND X in the fully-queried range (the coverage proof).
                                        const query_ok = self.skip_canon_produced != null;
                                        var x_present = false;
                                        var lower_slot: ?u64 = null; // highest produced L in [lo, X)
                                        var higher_slot: ?u64 = null; // lowest produced H in (X, hi]
                                        if (self.skip_canon_produced) |produced| {
                                            for (produced) |p| {
                                                if (p == slot) {
                                                    x_present = true;
                                                } else if (p >= lo and p < slot) {
                                                    if (lower_slot == null or p > lower_slot.?) lower_slot = p;
                                                } else if (p > slot and p <= hi) {
                                                    if (higher_slot == null or p < higher_slot.?) higher_slot = p;
                                                }
                                            }
                                        }
                                        // Pure firewall: ALL of (query ok) ∧ (X absent from produced list) ∧
                                        // (produced L<X) ∧ (produced H>X) ∧ (X phantom/incomplete) must hold.
                                        // The bypass is AUTOMATIC — a produced L<X and H>X with X absent IS
                                        // Blockstore::is_skipped (the canonical chain routes L→…→H around X).
                                        if (repair_escalate.clusterConfirmedSkip(
                                            query_ok,
                                            x_present,
                                            lower_slot != null,
                                            higher_slot != null,
                                            slot_info.knows_last_shred,
                                        )) {
                                            // ABANDON X: drop it from the in-progress set so it is no longer
                                            // the mandatory contiguous bridge. The canonical successor then
                                            // CHAIN-WAKEs on its real (frozen) parent and the freeze-tip
                                            // advances. In-process — NO fail-stop, NO exit.
                                            // ABANDON mutation (clearCompletedSlot + zero the nine stuck-slot
                                            // atomics) extracted to repair_abandon.zig so it is unit-PROVEN
                                            // (zig build test-repair-abandon), not reasoned-correct in place.
                                            // Byte-identical to the prior inline sequence. Resetting the
                                            // atomics (stuck_slot := 0 → prev_stuck != next_slot) forces the
                                            // next repair cycle to re-evaluate the NEW lowest in-progress slot
                                            // from scratch (mirror the identity-change reset above). The KATs
                                            // prove the freeze-tip advances 195→197: the canonical descendant
                                            // 197 is keyed on its REAL frozen parent 195 (NOT the skipped 196)
                                            // and wakes via the ordinary CHAIN-WAKE path independent of X.
                                            repair_abandon.abandonStuckSlot(self.shred_assembler, .{
                                                .slot = &self.stuck_slot,
                                                .since_ns = &self.stuck_slot_since_ns,
                                                .progress_ns = &self.stuck_slot_progress_ns,
                                                .progress_count = &self.stuck_slot_progress_count,
                                                .last_hwi_rederive_ns = &self.stuck_slot_last_hwi_rederive_ns,
                                                .failstop_armed_ns = &self.stuck_slot_failstop_armed_ns,
                                                .requests = &self.stuck_slot_requests,
                                                .resp_count = &self.stuck_slot_resp_count,
                                                .last_warn_ns = &self.stuck_slot_last_warn_ns,
                                            }, slot);
                                            std.log.warn("[REPAIR-SKIP-ABANDONED] slot={d} cluster-confirmed skipped via getBlocks (L={d} H={d} range=[{d},{d}]); dropped from in-progress + repair set instead of fail-stop — Agave set_root/prune_non_rooted analog", .{
                                                slot,
                                                lower_slot.?,
                                                higher_slot.?,
                                                lo,
                                                hi,
                                            });
                                            // TODO(pending_chain rekey): a pending_chain entry keyed on
                                            // target_parent == X (a deferred slot waiting for X to freeze)
                                            // would wait forever now that X is abandoned. There is NO clean
                                            // public "drop pending entries whose target_parent == X" API on
                                            // ReplayStage — markSlotDead is keyed on the slot ITSELF, cascades
                                            // into fork_choice / purgeUnrootedSlot, and is REPLAY-thread-only
                                            // (unsafe to call from this TVU repair thread). We rely on
                                            // CHAIN-WAKE via the real parent: the replay loop's 200ms
                                            // checkPendingChain drain wakes any deferred child once ITS true
                                            // parent freezes, and the 5-min pending_chain TTL GCs the rest. If
                                            // the offline-replay gate shows this is insufficient, add a
                                            // thread-safe ReplayStage.dropPendingChainForTargetParent(X) and
                                            // call it here (do NOT reach into pending_chain from this thread).
                                            continue; // skip HWI-rederive + fail-stop for the abandoned X
                                        }
                                    }
                                }

                                // (a) HighestWindowIndex RE-DERIVE: ask peers for the
                                // true highest/last shred. The response returns as an
                                // ordinary shred through processRepairResponse →
                                // processShred → assembler insert; if our last_index was
                                // null (dropped-LAST phantom), the on-boundary LAST_IN_SLOT
                                // shred sets the correct bound and the phantom loop breaks.
                                // BEST-EFFORT only (see deviations): in CASE 2 the repair
                                // loop already fires HWI every cycle, and a too-HIGH phantom
                                // last_index rejects a lower correct LAST as spurious
                                // (shred.zig:664). The fail-stop (b) is the GUARANTEED
                                // reliever. Throttled to once / 30s. shred_idx=0 → "highest".
                                const last_hwi = self.stuck_slot_last_hwi_rederive_ns.load(.acquire);
                                if (tnow - last_hwi > 30 * @as(i128, std.time.ns_per_s)) {
                                    self.stuck_slot_last_hwi_rederive_ns.store(tnow, .release);
                                    self.requestHighestWindowIndex(slot, 0) catch |e| {
                                        std.log.warn("[REPAIR-STUCK-ESCALATE] slot={d} HWI re-derive send err={any}", .{ slot, e });
                                    };
                                    std.log.warn("[REPAIR-STUCK-ESCALATE] slot={d} phantom-index signature (knows_last={} reqs={d} resp={d} stuck_ms={d}); fired HighestWindowIndex RE-DERIVE to recompute completion bound from peers", .{
                                        slot, slot_info.knows_last_shred, reqs, resps, @divTrunc(stuck_ns, std.time.ns_per_ms),
                                    });
                                }

                                // (b) FAIL-STOP FLOOR (Agave #28596 analog): if the same
                                // slot is STILL wedged past STUCK_FAILSTOP_NS, the HWI
                                // re-derive did not break it → clean controlled exit. The
                                // operator's fresh-snapshot restart (MANUAL — no auto-restart
                                // wrapper / systemd unit in the launch script) then recovers.
                                // NEVER skip/abandon the slot. Gated by VEX_REPAIR_STUCK_FAILSTOP
                                // (default ON; set to "0" to disable). Env read once + cached.
                                // `or inject_hit`: in a GATE build the injector bypasses the 5-min
                                // fail-stop timer too, so the OLD leg (VEX_REPAIR_SKIP_ABANDONED unset)
                                // reaches [REPAIR-STUCK-FAILSTOP] this cycle. inject_hit is a comptime
                                // `false` in a normal build ⇒ this collapses to `stuck_ns > STUCK_FAILSTOP_NS`.
                                if (stuck_ns > STUCK_FAILSTOP_NS or inject_hit) {
                                    if (self.stuck_slot_failstop_armed_ns.load(.acquire) == 0) {
                                        self.stuck_slot_failstop_armed_ns.store(tnow, .release);
                                    }
                                    if (repairStuckFailstopEnabled()) {
                                        const miss2 = self.shred_assembler.getMissingIndices(slot) catch &[_]u32{};
                                        defer if (miss2.len > 0) self.allocator.free(miss2);
                                        std.log.err("[REPAIR-STUCK-FAILSTOP] slot={d} phantom-index wedge UNRECOVERABLE in-process: knows_last={} missing={any} requests_sent={d} resp_for_slot={d} stuck_ms={d}. HighestWindowIndex re-derive did not break the loop. CLEAN FAIL-STOP (Agave #28596 floor) — exit so a fresh-snapshot restart recovers; slot is NOT skipped. Disable with VEX_REPAIR_STUCK_FAILSTOP=0.", .{
                                            slot,
                                            slot_info.knows_last_shred,
                                            miss2[0..@min(miss2.len, 4)],
                                            reqs,
                                            resps,
                                            @divTrunc(stuck_ns, std.time.ns_per_ms),
                                        });
                                        // std.log writes directly to stderr (no buffering),
                                        // so the [REPAIR-STUCK-FAILSTOP] line above lands
                                        // before exit. Exit 70 (EX_SOFTWARE) = a distinct,
                                        // non-zero "controlled software fail-stop" marker in
                                        // the logs/wrapper output. No auto-restart wrapper
                                        // consumes it (the launch script `exec`s with no loop /
                                        // systemd unit) — recovery is the operator's existing
                                        // fresh-snapshot restart.
                                        std.posix.exit(70);
                                    } else {
                                        const FsDbg = struct {
                                            var warned: bool = false;
                                        };
                                        if (!FsDbg.warned) {
                                            FsDbg.warned = true;
                                            std.log.warn("[REPAIR-STUCK-FAILSTOP] slot={d} would FAIL-STOP (phantom wedge >5min) but VEX_REPAIR_STUCK_FAILSTOP=0 disables it; staying up (operator opted out)", .{slot});
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (slot_info.knows_last_shred) {
                // CASE 1: We know the total — request specific missing indices
                const missing = self.shred_assembler.getMissingIndices(slot) catch continue;
                defer self.allocator.free(missing);
                if (missing.len == 0) continue;

                // DEDUP: Filter out recently-requested indices
                // Sig requests ALL missing shreds; we cap at 2048 per slot for safety
                var filtered_indices: [2048]u32 = undefined;
                var filtered_count: usize = 0;
                for (missing[0..@min(missing.len, 2048)]) |idx| {
                    if (self.shouldRequestRepair(slot, idx)) {
                        if (filtered_count < 2048) {
                            filtered_indices[filtered_count] = idx;
                            filtered_count += 1;
                        }
                    }
                }

                if (filtered_count > 0) {
                    // d27x: clamp to the remaining global budget so the
                    // closest-to-root slots (visited first thanks to the
                    // ascending sort above) get their full repair quota,
                    // and later slots get whatever is left or skipped.
                    const budget_left = AGAVE_MAX_REPAIR_LENGTH - total_repair_requests;
                    const to_send = @min(filtered_count, budget_left);
                    try self.requestRepairs(slot, filtered_indices[0..to_send]);
                    total_repair_requests += to_send;
                    // FIX B2 (LOG ONLY): if this is the tracked stuck slot, count
                    // the requests we issued for it so [REPAIR-STUCK] can report
                    // requests_sent vs resp_for_slot. No control-flow change.
                    if (slot == self.stuck_slot.load(.acquire)) {
                        _ = self.stuck_slot_requests.fetchAdd(to_send, .monotonic);
                    }
                }

                const needed = slot_info.last_shred_index + 1;
                const pct = (slot_info.unique_count * 100) / needed;
                if (pct > 50 or @mod(slot, 5000) == 0) {
                    std.log.debug("[REPAIR] Slot {d}: {d}/{d} ({d}%), requesting {d}/{d} missing (dedup filtered)\n", .{
                        slot, slot_info.unique_count, needed, pct, filtered_count, missing.len,
                    });
                }
            } else {
                // CASE 2: We DON'T know last_index yet.
                // Send ONE HighestWindowIndex to discover it, PLUS request
                // actual GAPS in the range [0..highest_received]. The old code
                // explored BEYOND highest, missing all the real holes below it.
                const highest_idx = self.shred_assembler.getHighestIndex(slot) catch 0;

                // Send HWI once (dedup prevents re-sending within 2s)
                if (self.shouldRequestRepair(slot, std.math.maxInt(u32))) {
                    try self.requestHighestWindowIndex(slot, 0);
                    // HWI is its own type-9 request, not counted against the
                    // WindowIndex (type-8) budget — but it does consume a peer
                    // send slot, so charge it 1 against the global cap.
                    total_repair_requests += 1;
                    // FIX #3 (2026-06-14): count CASE 2 (knows_last=FALSE) sends into
                    // stuck_slot_requests too. WITHOUT this the dropped-LAST phantom
                    // (last_index never set → CASE 2 forever) can never reach the
                    // phantom_signature (reqs>=200) gate, so its escalation/fail-stop
                    // would be dead. Mirror of the CASE 1 counter below.
                    if (slot == self.stuck_slot.load(.acquire)) {
                        _ = self.stuck_slot_requests.fetchAdd(1, .monotonic);
                    }
                }

                // Request ACTUAL GAPS from [0..highest_received] — not indices beyond.
                // This fills the real holes in the slot instead of probing into void.
                var gap_indices: [2048]u32 = undefined;
                var gap_count: usize = 0;
                var scan_idx: u32 = 0;
                while (scan_idx <= highest_idx and gap_count < 2048) : (scan_idx += 1) {
                    if (!self.shred_assembler.hasShred(slot, scan_idx)) {
                        if (self.shouldRequestRepair(slot, scan_idx)) {
                            gap_indices[gap_count] = scan_idx;
                            gap_count += 1;
                        }
                    }
                }

                if (gap_count > 0) {
                    const budget_left = if (total_repair_requests >= AGAVE_MAX_REPAIR_LENGTH) 0 else AGAVE_MAX_REPAIR_LENGTH - total_repair_requests;
                    const to_send = @min(gap_count, budget_left);
                    if (to_send > 0) {
                        try self.requestRepairs(slot, gap_indices[0..to_send]);
                        total_repair_requests += to_send;
                        // FIX #3: count CASE 2 gap requests for the tracked stuck slot
                        // (see HWI counter above) so the dropped-LAST phantom can escalate.
                        if (slot == self.stuck_slot.load(.acquire)) {
                            _ = self.stuck_slot_requests.fetchAdd(to_send, .monotonic);
                        }
                    }
                }

                if (@mod(slots_repaired, 10) == 0 and gap_count > 0) {
                    std.log.debug("[REPAIR] Slot {d}: gaps {d} in [0..{d}] (have {d}, dedup={d})\n", .{
                        slot, gap_count, highest_idx, slot_info.unique_count, self.repair_dedup.count(),
                    });
                }
            }
            slots_repaired += 1;
        }

        // ── [REPAIR-INFLIGHT] HOLE-SLOT HWI (gated, 2026-07-06) ──────────────
        // Spend LEFTOVER request budget on HighestWindowIndex discovery for the
        // first K absent slots in (consensus_root, lowest_in_progress). Every
        // slot strictly between the consensus root and the lowest in-progress
        // slot has ZERO shreds in the assembler (by definition of the sorted
        // in-progress set), so nothing above walks it — pre-lever those hole
        // slots waited for the 30s/5s catch-up seed timer or the orphan pass.
        // Agave walks EVERY repair-tree slot each iteration
        // (repair_weight.get_best_weighted_repairs → generate_repairs_for_slot
        // — no seed timer); this reproduces that per-cycle coverage for the
        // bridge holes. Dedup-keyed exactly like the existing HWI sends (key
        // idx=maxInt(u32), 200ms TTL) and charged 1/slot against the same
        // AGAVE_MAX_REPAIR_LENGTH budget + cycle_deadline. Gate OFF ⇒ block
        // never runs ⇒ byte-identical behavior.
        if (self.repair_inflight_enabled and root_slot_for_filter > 0 and
            total_repair_requests < AGAVE_MAX_REPAIR_LENGTH)
        {
            // Lowest in-progress slot ABOVE the consensus root (slots[] is
            // sorted ascending; pre-root entries were skipped by the filter).
            var lowest_inprog: u64 = 0;
            for (slots) |s| {
                if (s > root_slot_for_filter) {
                    lowest_inprog = s;
                    break;
                }
            }
            if (lowest_inprog > root_slot_for_filter + 1) {
                const HOLE_HWI_MAX_PER_CYCLE: usize = 32; // K: first 32 absent slots each cycle
                var hole_emitted: usize = 0;
                var hole_slot: u64 = root_slot_for_filter + 1;
                while (hole_slot < lowest_inprog and hole_emitted < HOLE_HWI_MAX_PER_CYCLE and
                    total_repair_requests < AGAVE_MAX_REPAIR_LENGTH) : (hole_slot += 1)
                {
                    if (std.time.nanoTimestamp() >= cycle_deadline) break;
                    if (self.shouldRequestRepair(hole_slot, std.math.maxInt(u32))) {
                        self.requestHighestWindowIndex(hole_slot, 0) catch continue;
                        total_repair_requests += 1;
                        hole_emitted += 1;
                    }
                }
                if (hole_emitted > 0) {
                    const HoleDbg = struct {
                        var last_ns: i128 = 0;
                    };
                    const hnow = std.time.nanoTimestamp();
                    if (hnow - HoleDbg.last_ns > 5 * std.time.ns_per_s) {
                        HoleDbg.last_ns = hnow;
                        std.log.warn("[REPAIR-INFLIGHT] hole-slot HWI: emitted={d} range=({d},{d}) budget_used={d}/{d}", .{
                            hole_emitted, root_slot_for_filter, lowest_inprog, total_repair_requests, AGAVE_MAX_REPAIR_LENGTH,
                        });
                    }
                }
            }
        }

        // PR-5r diagnostic: throttled emit when pre-root slots were skipped
        // by the new filter. Throttled to once per 200 invocations to avoid
        // log spam during steady-state where some pre-root churn is normal.
        if (pre_root_skipped > 0) {
            const Pr5rDbg = struct {
                var calls: u64 = 0;
            };
            Pr5rDbg.calls += 1;
            if (Pr5rDbg.calls % 50 == 1) {
                std.log.warn("[PR-5r] pre_root_skipped={d} (root={d}, total_slots={d}, repaired={d}, requests={d})", .{
                    pre_root_skipped, root_slot_for_filter, slots.len, slots_repaired, total_repair_requests,
                });
            }
        }

        // d27y (2026-05-11): proactive next-slot probe based on root_bank.
        // Agave's repair_weight traverses the rooted-tree starting at root_bank
        // and `get_best_unknown_last_index` (repair_weight.rs:595-619) generates
        // repair requests for slots even when blockstore has no meta — that's
        // how it bootstrap-discovers the chain-extending slots ahead of root.
        //
        // Vexor's shred_assembler only tracks slots once at least one shred
        // arrives; the slots-loop above iterates only `getInProgressSlots()`,
        // so a slot we've never received ANY shred for (e.g. root_bank+1 when
        // root_bank just advanced past a gap) gets zero repair attention even
        // though it's the next chain-extending slot.
        //
        // Empirical evidence: after d27x advanced the chain 475 slots, it
        // stalled at root_bank=407726063 with root+2/+3 already COMPLETE in
        // assembler but root+1 (407726064) at count=0, wi_req=0 — never
        // requested because not in the in-progress list.
        // 2026-05-27 (FIX #48 primary): replace the +50 distance ceiling with
        // a max_slot_seen upper bound, capped by MAX_UNKNOWN_LAST_INDEX_REPAIRS_PER_ITER.
        // Agave-canonical: get_best_unknown_last_index iterates the WHOLE repair tree
        // (no slot-distance ceiling); bound is count-per-iter (MAX_UNKNOWN_LAST_INDEX_REPAIRS=10
        // at repair_service.rs:351). The prior +50 ceiling left slots root+51..max_seen
        // completely uncovered when the cluster-to-root gap exceeded 50 (verified live
        // 2026-05-26 wedge: bridge 411130212-411135794 received zero shreds).
        //
        // 2026-05-27 (FIX #48.1 CRITICAL HOTFIX): emit cap REDUCED 200 → 50 after
        // gdb-confirmed CPU saturation. requestHighestWindowIndex calls keypair.sign()
        // ONCE PER PEER (hwi_fanout=6 peers). At 200 emits/iter × 6 signs × 20Hz repair
        // cadence = 24,000 ed25519 signs/sec required. Zig stdlib ed25519 sign throughput
        // on znver4 ReleaseSafe is ~10-15K signs/sec → TVU thread saturates at 95% CPU,
        // can't drain repair responses → validator wedges at 4 banks/min freeze rate.
        // At 50 emits/iter the load is 50 × 6 × 20Hz = 6,000 signs/sec, comfortably below
        // throughput. The prior +50 ceiling worked empirically for the same reason.
        //
        // SAFETY CAP (advisor #2): bound the *scan* (not just emits) so we don't
        // walk thousands of slots acquiring shred_assembler.mutex per iter when
        // most slots are dedup-blocked. shred_assembler.mutex is on the shred-receive
        // hot path; even with 0 emits we'd grab the mutex once per scanned slot.
        // 500-slot scan × 5500-slot gap = 11 calls to fully cover. Within dedup
        // TTL (200ms), 11 calls × 200ms = ~2.2s for full sweep — acceptable.
        const MAX_UNKNOWN_LAST_INDEX_REPAIRS_PER_ITER: u64 = 50;
        const MAX_PROBE_SCAN_PER_ITER: u64 = 500;
        if (self.slot_sink) |rs| {
            if (rs.rootBank()) |rb| {
                const rb_slot = rb.slot;
                const max_seen_for_probe = self.stats.max_slot_seen.load(.monotonic);
                var probe_off: u64 = 1;
                var unknown_last_emitted: u64 = 0;
                while (rb_slot + probe_off <= max_seen_for_probe and
                    total_repair_requests < AGAVE_MAX_REPAIR_LENGTH and
                    unknown_last_emitted < MAX_UNKNOWN_LAST_INDEX_REPAIRS_PER_ITER and
                    probe_off <= MAX_PROBE_SCAN_PER_ITER) : (probe_off += 1)
                {
                    const probe = rb_slot + probe_off;
                    const info = self.shred_assembler.getSlotInfo(probe) catch continue;
                    // Only probe if NOT yet in assembler (count=0 means either
                    // no entry or empty entry — either way we need to ask peers).
                    if (!info.knows_last_shred and info.unique_count == 0) {
                        if (self.shouldRequestRepair(probe, std.math.maxInt(u32))) {
                            self.requestHighestWindowIndex(probe, 0) catch continue;
                            total_repair_requests += 1;
                            unknown_last_emitted += 1;
                        }
                    }
                }
                // Diag: log when the broad probe found any work to do (helps
                // confirm the fix is firing on bridge gaps post-deploy).
                if (unknown_last_emitted > 50) {
                    std.log.warn("[REPAIR-BROAD-PROBE] rb_slot={d} max_seen={d} emitted={d} HWI", .{
                        rb_slot, max_seen_for_probe, unknown_last_emitted,
                    });
                }
            }
        }

        // === Proactive future slot discovery === @prov:tvu.lookahead-probe
        // Probes slot+1 and a random future slot to detect being behind.
        // This helps discover new slots from peers before turbine delivers them.
        if (network_head > 0 and slots.len > 0) {
            // Probe the next slot beyond what we're tracking
            const next_slot = network_head + 1;
            if (self.shouldRequestRepair(next_slot, std.math.maxInt(u32))) {
                self.requestHighestWindowIndex(next_slot, 0) catch |err| {
                    std.log.debug("[TVU lookahead-next] requestHighestWindowIndex err: {any}\n", .{err});
                };
            }

            // Probe a random slot 10-50 ahead (like Sig's jittered lookahead)
            // Uses a simple hash-based pseudo-random offset to avoid needing a PRNG
            const jitter: u64 = 10 + @mod(network_head *% 7919, 41); // pseudo-random 10..50
            const probe_slot = network_head + jitter;
            if (self.shouldRequestRepair(probe_slot, std.math.maxInt(u32))) {
                self.requestHighestWindowIndex(probe_slot, 0) catch |err| {
                    std.log.debug("[TVU lookahead-probe] requestHighestWindowIndex err: {any}\n", .{err});
                };
            }
        }
    }

    /// Get pending slots ready for replay
    pub fn getPendingSlots(self: *Self) []const core.Slot {
        return self.pending_slots.items;
    }

    /// Clear a pending slot after replay
    /// CRITICAL: Also removes from shred_assembler to prevent memory leak
    pub fn clearPendingSlot(self: *Self, slot: core.Slot) void {
        for (self.pending_slots.items, 0..) |s, i| {
            if (s == slot) {
                _ = self.pending_slots.orderedRemove(i);
                // Remove from assembler to free memory
                self.shred_assembler.removeSlot(slot);
                break;
            }
        }
    }

    /// Print statistics
    pub fn printStats(self: *const Self) void {
        std.log.debug(
            \\
            \\═══ TVU Statistics ═══
            \\Shreds received:  {}
            \\Shreds inserted:  {}
            \\Shreds duplicate: {}
            \\Shreds invalid:   {}
            \\Repairs sent:     {}
            \\Repairs received: {}
            \\Slots completed:  {}
            \\══════════════════════
            \\
        , .{
            self.stats.shreds_received.load(.seq_cst),
            self.stats.shreds_inserted.load(.seq_cst),
            self.stats.shreds_duplicate.load(.seq_cst),
            self.stats.shreds_invalid.load(.seq_cst),
            self.stats.repairs_sent.load(.seq_cst),
            self.stats.repairs_received.load(.seq_cst),
            self.stats.slots_completed.load(.seq_cst),
        });
    }
};

/// Turbine protocol helper - proper stake-weighted tree implementation
/// @prov:turbine.tree
pub const Turbine = struct {
    allocator: std.mem.Allocator,

    /// The turbine tree for computing shred destinations
    tree: ?*turbine_tree.TurbineTree,

    /// Cached children for current shred
    children: std.ArrayListUnmanaged(turbine_tree.TurbineNode),

    /// Shred retransmit peers (for legacy compatibility)
    retransmit_peers: std.ArrayListUnmanaged(packet.SocketAddr),

    /// Guards the turbine tree's `nodes` backing across the cross-thread rebuild
    /// (core 4 buildTree/tree.build) vs. the leader-broadcast read (core 20
    /// collectBroadcastTargets). Uncontended in practice: build fires every 30s,
    /// the read only on our leader slots. Default-init so Turbine.init is unchanged.
    tree_mtx: std.Thread.Mutex = .{},

    const Self = @This();

    /// Fanout constant. @prov:turbine.tree
    pub const DATA_PLANE_FANOUT: usize = 200;

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .tree = null,
            .children = .empty,
            .retransmit_peers = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.tree) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }
        self.children.deinit(self.allocator);
        self.retransmit_peers.deinit(self.allocator);
    }

    /// Initialize the turbine tree with our identity
    pub fn initTree(self: *Self, my_pubkey: core.Pubkey) !void {
        if (self.tree) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }

        const tree = try self.allocator.create(turbine_tree.TurbineTree);
        tree.* = turbine_tree.TurbineTree.init(self.allocator, my_pubkey);
        self.tree = tree;
    }

    /// Build the tree from gossip peers and stake info
    pub fn buildTree(
        self: *Self,
        gossip_peers: []const gossip.ContactInfo,
        staked_nodes: *const std.AutoHashMap([32]u8, u64),
    ) !void {
        if (self.tree) |tree| {
            // Scope the lock to JUST tree.build() (not the gossip contacts_rw
            // region in the caller updateTurbineTree) so tree_mtx nests strictly
            // inside contacts_rw with no inverse ordering → no deadlock.
            self.tree_mtx.lock();
            defer self.tree_mtx.unlock();
            try tree.build(gossip_peers, staked_nodes);
        }
    }

    /// leader_mode broadcast targets: the top-`max` highest-stake peers with a TVU address (tree.nodes
    /// are sorted stake-desc; our own node has tvu_addr=null so it's skipped). We over-broadcast each
    /// produced shred to all of them for robust propagation. LIVENESS-only — the canonical single-root
    /// stake-weighted-shuffle target (@prov:turbine.broadcast-peer) is a later refinement, blocked on a
    /// working ChaChaRng/WeightedShuffle (the orphaned getRetransmitChildren never compiled its own).
    pub fn collectBroadcastTargets(self: *Self, out: *std.ArrayListUnmanaged(packet.SocketAddr), max: usize) void {
        // Lock BEFORE the tree deref so all three early exits (orelse return /
        // break / catch return) release via defer. Guards against a concurrent
        // tree.build() on core 4 reallocating/sorting tree.nodes mid-read.
        self.tree_mtx.lock();
        defer self.tree_mtx.unlock();
        const tree = self.tree orelse return;
        for (tree.nodes.items) |node| {
            if (out.items.len >= max) break;
            if (node.tvu_addr) |addr| out.append(self.allocator, addr) catch return;
        }
    }

    /// C1 — CANONICAL single-root broadcast target for one shred.
    /// @prov:turbine.broadcast-peer The leader (us = tree.my_pubkey)
    /// picks ONE turbine root per shred via the stake-weighted shuffle seeded by
    /// (slot, index, type). Returns that root's TVU addr, or null if the tree is
    /// empty / the root has no contact info (caller falls back / drops the shred).
    ///
    /// Held under `tree_mtx` (same discipline as collectBroadcastTargets): the
    /// cross-thread tree.build() on core 4 can realloc/sort tree.nodes + stakes
    /// mid-read, so the whole shuffle must run inside the lock.
    ///
    /// `use_cha_cha_8` MUST match the cluster's switch_to_chacha8_turbine (SIMD-0332)
    /// activation, else we pick a different root than the network expects (liveness-
    /// only: the shred is still re-propagated, never a validity issue).
    pub fn getBroadcastPeerForShred(
        self: *Self,
        slot: u64,
        shred_index: u32,
        is_data: bool,
        use_cha_cha_8: bool,
    ) ?packet.SocketAddr {
        self.tree_mtx.lock();
        defer self.tree_mtx.unlock();
        const tree = self.tree orelse return null;
        const shred_id = turbine_tree.ShredId{
            .slot = slot,
            .index = shred_index,
            .shred_type = if (is_data) .data else .code,
        };
        // We are the leader for our own produced block.
        const node = (tree.getBroadcastPeer(tree.my_pubkey, shred_id, use_cha_cha_8) catch return null) orelse return null;
        return node.tvu_addr;
    }

    /// Calculate retransmit peers based on stake (legacy API)
    pub fn calculateRetransmitPeers(
        self: *Self,
        cluster_nodes: []const gossip.ContactInfo,
        our_index: usize,
    ) !void {
        self.retransmit_peers.clearRetainingCapacity();

        // Legacy fallback: simple index-based calculation
        // TODO: Remove once tree-based calculation is fully integrated
        const fanout: usize = DATA_PLANE_FANOUT;
        const start = our_index * fanout;
        const end = @min(start + fanout, cluster_nodes.len);

        for (cluster_nodes[start..end]) |node| {
            try self.retransmit_peers.append(self.allocator, node.tvu_addr);
        }
    }

    /// Calculate retransmit children for a specific shred (proper implementation)
    /// This is the correct way to compute Turbine destinations
    pub fn getRetransmitChildrenForShred(
        self: *Self,
        leader: core.Pubkey,
        slot: u64,
        shred_index: u32,
        is_data: bool,
        use_cha_cha_8: bool,
    ) !turbine_tree.TurbineSearchResult {
        const tree = self.tree orelse return turbine_tree.TurbineSearchResult{ .my_index = 0, .root_distance = 0 };

        const shred_id = turbine_tree.ShredId{
            .slot = slot,
            .index = shred_index,
            .shred_type = if (is_data) .data else .code,
        };

        return try tree.getRetransmitChildren(
            &self.children,
            leader,
            shred_id,
            DATA_PLANE_FANOUT,
            use_cha_cha_8,
        );
    }

    /// turbine-retransmit (gated): compute this node's turbine-tree children for a
    /// RECEIVED shred and copy their TVU addresses into `out` (caller-owned), all
    /// under `tree_mtx` so the cross-thread `tree.build()` on core 4 can't realloc
    /// `tree.nodes`/`stakes` mid-shuffle (same discipline as getBroadcastPeerForShred).
    /// Uses an internal scratch list (not self.children) so it never aliases the
    /// leader-broadcast path's `children`. Returns the number of targets written.
    /// No-ops safely (returns 0) when the tree is empty / unpopulated. LIVENESS-only:
    /// a wrong/empty child set only degrades fan-out, never block validity.
    pub fn collectRetransmitTargetsForShred(
        self: *Self,
        out: *std.ArrayListUnmanaged(packet.SocketAddr),
        leader: core.Pubkey,
        slot: u64,
        shred_index: u32,
        is_data: bool,
        use_cha_cha_8: bool,
    ) usize {
        self.tree_mtx.lock();
        defer self.tree_mtx.unlock();
        const tree = self.tree orelse return 0;
        if (tree.nodes.items.len == 0) return 0;

        const shred_id = turbine_tree.ShredId{
            .slot = slot,
            .index = shred_index,
            .shred_type = if (is_data) .data else .code,
        };

        var scratch = std.ArrayList(turbine_tree.TurbineNode){};
        defer scratch.deinit(self.allocator);
        _ = tree.getRetransmitChildren(&scratch, leader, shred_id, DATA_PLANE_FANOUT, use_cha_cha_8) catch return 0;

        var n: usize = 0;
        for (scratch.items) |child| {
            if (child.tvu_addr) |addr| {
                out.append(self.allocator, addr) catch break;
                n += 1;
            }
        }
        return n;
    }

    /// Get the number of children computed for the current shred
    pub fn getChildCount(self: *const Self) usize {
        return self.children.items.len;
    }

    /// Get children nodes for broadcasting (for leader block production)
    /// Returns null if no children have been computed
    pub fn getChildren(self: *const Self) ?[]const turbine_tree.TurbineNode {
        if (self.children.items.len == 0) return null;
        return self.children.items;
    }

    /// Retransmit shred to peers (legacy)
    pub fn retransmit(self: *Self, shred_data: []const u8, sock: *socket.UdpSocket) !usize {
        var sent: usize = 0;

        for (self.retransmit_peers.items) |peer| {
            var pkt = packet.Packet.init();
            @memcpy(pkt.data[0..shred_data.len], shred_data);
            pkt.len = @intCast(shred_data.len);
            pkt.src_addr = peer;

            if (sock.send(&pkt) catch null) |_| {
                sent += 1;
            }
        }

        return sent;
    }

    /// Retransmit shred to computed children (proper implementation)
    pub fn retransmitToChildren(self: *Self, shred_data: []const u8, sock: *socket.UdpSocket) !usize {
        var sent: usize = 0;

        for (self.children.items) |child| {
            if (child.tvu_addr) |addr| {
                var pkt = packet.Packet.init();
                @memcpy(pkt.data[0..shred_data.len], shred_data);
                pkt.len = @intCast(shred_data.len);
                pkt.src_addr = addr;

                if (sock.send(&pkt) catch null) |_| {
                    sent += 1;
                }
            }
        }

        return sent;
    }
};

// Import turbine_tree module
const turbine_tree = @import("turbine_tree.zig");

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "tvu service init" {
    var service = try TvuService.init(std.testing.allocator, .{});
    defer service.deinit();

    try std.testing.expect(!service.running.load(.seq_cst));
}

test "tvu repair request" {
    const allocator = std.testing.allocator;
    var keypair = core.Keypair.generate();
    var service = try TvuService.init(allocator, .{
        .enable_af_xdp = false,
        .enable_io_uring = false,
        .keypair = &keypair,
    });
    defer service.deinit();

    var sock = try socket.UdpSocket.init();
    try sock.bindPort(0);
    service.repair_socket = sock;

    const peer = TvuService.RepairPeer{
        .addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 9999),
        .pubkey = [_]u8{0} ** 32,
    };
    try service.setRepairPeersOverride(&[_]TvuService.RepairPeer{peer});
    try service.requestRepairs(123, &[_]u32{1});

    const sent = service.stats.repairs_sent.load(.seq_cst);
    try std.testing.expect(sent > 0);
}

test "turbine" {
    var turbine = Turbine.init(std.testing.allocator);
    defer turbine.deinit();

    try std.testing.expectEqual(@as(usize, 0), turbine.retransmit_peers.items.len);
    try std.testing.expectEqual(@as(usize, 0), turbine.getChildCount());
}

// TEST STRING - REMOVE AFTER VERIFICATION
const TEST_VERIFICATION_STRING = "TVU_FILE_COMPILED_12345";

/// AF_XDP receive self-test (diagnostic; NOT used by the validator `run` path).
///
/// Binds ONE XSK socket to `interface` queue `queue_id` through the REAL
/// SharedXdpManager.registerSocket + AcceleratedIO path (the exact code the
/// validator uses), attaches the pinned XDP program, then polls RX for
/// `duration_s` seconds and reports how many packets were delivered via the
/// AF_XDP fast path. Lets us validate the AF_XDP receive pipeline — including the
/// XSKMAP bind-queue keying fix — on a veth pair (use_driver=false → SKB/generic
/// mode, zero NIC risk) or a dedicated NIC port (use_driver=true → driver mode)
/// WITHOUT running a full validator.
///
/// Prerequisite: run setup-xdp-vexor.sh <interface> first to compile + pin
/// /sys/fs/bpf/vexor/{prog,xsks_map,port_filter}, and populate port_filter with
/// the port(s) to redirect. Requires CAP_NET_RAW + CAP_NET_ADMIN + CAP_BPF (run
/// as root, or setcap the binary).
pub fn runXdpSelfTest(
    allocator: std.mem.Allocator,
    interface: []const u8,
    queue_id: u32,
    port: u16,
    duration_s: u64,
    use_driver: bool,
    zero_copy: bool,
) !void {
    const mode: shared_xdp.AttachMode = if (use_driver) .driver else .skb;
    std.log.warn("[XDP-SELFTEST] iface={s} queue={d} port={d} duration={d}s mode={s} zero_copy={}", .{
        interface, queue_id, port, duration_s, @tagName(mode), zero_copy,
    });

    const ports = [_]u16{port};
    const mgr = try shared_xdp.SharedXdpManager.init(allocator, interface, &ports, mode);
    defer mgr.deinit();

    // Attach BEFORE socket creation: xsk_bind() requires an active XDP program on
    // the interface (FIX #92 ordering — same as tryStartAcceleratedIO).
    try mgr.attach();
    std.log.warn("[XDP-SELFTEST] XDP program attached to {s} (mode={s})", .{ interface, @tagName(mode) });

    const io = try accelerated_io.AcceleratedIO.init(allocator, .{
        .interface = interface,
        .bind_port = port,
        .queue_id = queue_id,
        .shared_xdp = mgr,
        .prefer_xdp = true,
        .umem_frame_count = 4096,
        .zero_copy = zero_copy, // veth/SKB must be false; mlx5 driver mode can use true to test the real --xdp-zero-copy bind
    });
    defer io.deinit();

    if (!io.isKernelBypass()) {
        std.log.err("[XDP-SELFTEST] FAIL: socket did NOT bind to AF_XDP (fell back to kernel path) — XSK bind/registration failed.", .{});
        return error.XdpBindFailed;
    }
    std.log.warn("[XDP-SELFTEST] AF_XDP socket bound + registered in xsks_map[{d}] (map key == bind queue_id)", .{queue_id});

    const start_ms = std.time.milliTimestamp();
    const deadline_ms = start_ms + @as(i64, @intCast(duration_s * 1000));
    var total: u64 = 0;
    var last_report_ms = start_ms;

    while (std.time.milliTimestamp() < deadline_ms) {
        const pkts = io.receiveBatch(64) catch |e| {
            std.log.warn("[XDP-SELFTEST] receiveBatch error: {}", .{e});
            std.Thread.sleep(2 * std.time.ns_per_ms);
            continue;
        };
        total += pkts.len;
        const now_ms = std.time.milliTimestamp();
        if (now_ms - last_report_ms >= 1000) {
            std.log.warn("[XDP-SELFTEST] rx so far: {d} packets", .{total});
            last_report_ms = now_ms;
        }
        if (pkts.len == 0) std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    std.log.warn("[XDP-SELFTEST] ====== RESULT ======", .{});
    std.log.warn("[XDP-SELFTEST] iface={s} queue={d} port={d}: received {d} packets in {d}s", .{
        interface, queue_id, port, total, duration_s,
    });
    if (total > 0) {
        std.log.warn("[XDP-SELFTEST] PASS — AF_XDP receive pipeline delivered packets via xsks_map[{d}]", .{queue_id});
    } else {
        std.log.warn("[XDP-SELFTEST] 0 packets — no traffic sent, OR redirect/keying mismatch (xsks_map[rx_queue_index] not pointing at this socket)", .{});
    }
}
