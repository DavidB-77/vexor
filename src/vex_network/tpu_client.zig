//! Vexor TPU Client
//!
//! Transaction Processing Unit client for submitting transactions.
//! Reference: Firedancer src/disco/quic/fd_quic_tile.c
//!
//! The TPU client sends transactions to leader nodes using:
//! - UDP (legacy, simple but unreliable)
//! - QUIC (preferred, reliable with flow control)

const std = @import("std");
const core = @import("core");
const packet = @import("packet.zig");
const gossip = @import("gossip.zig");
const consensus = @import("vex_consensus");
const solana_quic = @import("solana_quic.zig");

/// TPU port offset from gossip port (Solana convention)
pub const TPU_PORT_OFFSET: u16 = 6;

/// Maximum transaction size
pub const MAX_TX_SIZE: usize = 1232;

/// Maximum pending transactions
pub const MAX_PENDING_TXS: usize = 256;

/// Max transactions per QUIC batch
pub const MAX_TX_BATCH: usize = 32;

/// Retry backoff for a pending vote that could NOT be sent this pass (no QUIC leader
/// resolved yet, or the QUIC batch returned 0). processPending runs ~every 1ms; without a
/// backoff it re-scans the FULL pending queue and re-calls the expensive getLeaderTpuQuicNoLock
/// (hashmap + clock syscall) for every not-yet-sendable vote ~1000x/sec → O(N²)/pass, ~40% of a
/// dedicated core at steady state. Stamping next_retry_at_ms caps re-attempts to ~20x/sec. 50ms
/// is well inside a ~400ms slot, so a vote for the CURRENT leader still retries promptly, and UDP
/// carries the vote regardless. Canonical: Firedancer fd_txsend rate-limits send/connect ATTEMPTS
/// (fd_txsend_tile.c:76-84) and Agave SendTransactionService retries on an interval, not every ms.
pub const RETRY_BACKOFF_MS: u64 = 50;

const LEADER_CACHE_TTL_SECS: i64 = 30;
const LEADER_NEGATIVE_CACHE_TTL_SECS: i64 = 5;
const QUIC_BACKOFF_BASE_MS: u64 = 200;
const QUIC_BACKOFF_MAX_MS: u64 = 4000;
const QUIC_BACKOFF_JITTER_MS: u64 = 50;
const QUIC_BATCH_LOG_EVERY: u64 = 50;

/// TPU connection type
pub const ConnectionType = enum {
    /// UDP connection (legacy, unreliable)
    udp,
    /// QUIC connection (reliable)
    quic,
};

/// TPU client for sending transactions
/// Reference: Firedancer fd_tpu_tile
pub const TpuClient = struct {
    allocator: std.mem.Allocator,

    /// UDP socket for legacy TPU
    udp_socket: ?std.posix.socket_t,

    /// QUIC client for modern TPU
    quic_client: ?*solana_quic.SolanaTpuQuic,
    enable_quic: bool,
    enable_h3_datagram: bool,
    force_quic: bool,
    enable_quic_coalesce: bool,
    quic_batch_size_override: u8,
    quic_batch_auto_cap: u8,
    quic_batch_success_streak: u8,
    quic_batch_fail_streak: u8,
    quic_batch_log_counter: u64,

    /// Reference to gossip service for peer discovery
    gossip_service: ?*gossip.GossipService,
    leader_schedule: ?*consensus.leader_schedule.LeaderScheduleCache,
    quic_insecure: bool,
    quic_port: u16,

    /// RPC URL for fallback leader lookup
    rpc_url: ?[]const u8 = null,
    /// QUIC target override for local testing
    quic_target_override: ?packet.SocketAddr = null,

    /// Leader TPU addresses (slot -> address)
    leader_tpu_cache: std.AutoHashMap(core.Slot, packet.SocketAddr),
    /// Leader TPU QUIC addresses (slot -> address)
    leader_tpu_quic_cache: std.AutoHashMap(core.Slot, packet.SocketAddr),
    leader_tpu_cache_ts: std.AutoHashMap(core.Slot, i64),
    leader_tpu_quic_cache_ts: std.AutoHashMap(core.Slot, i64),

    /// Negative lookup cache: tracks slots where leader lookup failed.
    /// Prevents repeated expensive gossip/RPC lookups for the same slot.
    /// Value is the timestamp of the failed lookup.
    failed_leader_lookups: std.AutoHashMap(core.Slot, i64),
    /// Counter for throttling "leader not found" log messages
    leader_miss_count: u64,

    /// Pending transactions waiting to be sent
    pending_txs: std.ArrayListUnmanaged(PendingTx),
    mutex: std.Thread.Mutex,

    /// Statistics
    stats: TpuStats,

    const Self = @This();

    pub const PendingTx = struct {
        data: []u8,
        target_slot: core.Slot,
        attempts: u32,
        timestamp: i64,
        next_retry_at_ms: u64,
    };

    pub const TpuStats = struct {
        txs_sent_udp: u64 = 0,
        txs_sent_quic: u64 = 0,
        txs_sent_quic_batches: u64 = 0,
        txs_sent_quic_batched: u64 = 0,
        txs_failed: u64 = 0,
        txs_dropped: u64 = 0,
        cache_hits: u64 = 0,
        cache_misses: u64 = 0,
        cache_refreshes: u64 = 0,
        quic_retries: u64 = 0,
        quic_backoffs: u64 = 0,
        /// 2026-07-10 vote-fanout hygiene: fanout targets skipped at ENQUEUE time because the leader
        /// has no resolvable QUIC address in gossip (no tpu_quic ContactInfo / stale/zero port). These
        /// used to be enqueued into the 256-deep pending ring and sit there until aged out ('dropped'),
        /// starving QUIC sends for RESOLVABLE leaders. UDP leg still carries their votes. A high value
        /// vs enqueued ⟹ many upcoming leaders lack a gossip QUIC endpoint (structural, not a bug).
        skipped_unresolvable: u64 = 0,
        /// 2026-07-10: fanout targets skipped at enqueue time because the leader's QUIC endpoint failed
        /// its handshake within the recent window (SolanaTpuQuic.isDeadCached). Prevents the ~8s
        /// reconnect hot-loop to leaders that don't run QUIC. UDP leg still carries their votes.
        dead_cache_hits: u64 = 0,
    };

    pub fn initDefault(allocator: std.mem.Allocator) !*Self {
        // Last arg = default TPU-QUIC port; aligned to the advertised
        // tpu_quic (tpu_port 8004 + 6 = 8010). Was 8009 (stale off-by-one).
        // The leader-TPU cache resolves the real per-peer port from gossip
        // (tpuQuic field), so this default is only a fallback.
        return init(allocator, true, true, false, true, 0, true, 8010);
    }

    pub fn init(
        allocator: std.mem.Allocator,
        enable_quic: bool,
        enable_h3_datagram: bool,
        force_quic: bool,
        enable_quic_coalesce: bool,
        quic_batch_size_override: u8,
        quic_insecure: bool,
        quic_port: u16,
    ) !*Self {
        const self = try allocator.create(Self);

        // Create UDP socket
        const udp_sock = std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM,
            0,
        ) catch |err| blk: {
            std.log.debug("[TpuClient] Failed to create UDP socket: {}\n", .{err});
            break :blk null;
        };

        self.* = Self{
            .allocator = allocator,
            .udp_socket = udp_sock,
            .quic_client = null,
            .enable_quic = enable_quic,
            .enable_h3_datagram = enable_h3_datagram,
            .force_quic = force_quic,
            .enable_quic_coalesce = enable_quic_coalesce,
            .quic_batch_size_override = quic_batch_size_override,
            .quic_batch_auto_cap = MAX_TX_BATCH,
            .quic_batch_success_streak = 0,
            .quic_batch_fail_streak = 0,
            .quic_batch_log_counter = 0,
            .quic_insecure = quic_insecure,
            .quic_port = quic_port,
            .gossip_service = null,
            .leader_schedule = null,
            .leader_tpu_cache = std.AutoHashMap(core.Slot, packet.SocketAddr).init(allocator),
            .leader_tpu_quic_cache = std.AutoHashMap(core.Slot, packet.SocketAddr).init(allocator),
            .leader_tpu_cache_ts = std.AutoHashMap(core.Slot, i64).init(allocator),
            .leader_tpu_quic_cache_ts = std.AutoHashMap(core.Slot, i64).init(allocator),
            .failed_leader_lookups = std.AutoHashMap(core.Slot, i64).init(allocator),
            .leader_miss_count = 0,
            .pending_txs = .{},
            .mutex = .{},
            .stats = TpuStats{},
        };

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.udp_socket) |sock| std.posix.close(sock);
        self.leader_tpu_cache.deinit();
        self.leader_tpu_quic_cache.deinit();
        self.leader_tpu_cache_ts.deinit();
        self.leader_tpu_quic_cache_ts.deinit();
        self.failed_leader_lookups.deinit();
        for (self.pending_txs.items) |*pending| {
            self.allocator.free(pending.data);
        }
        self.pending_txs.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn setQuicClient(self: *Self, quic_client: *solana_quic.SolanaTpuQuic) void {
        self.quic_client = quic_client;
        self.enable_quic = true;
    }

    pub fn setGossipService(self: *Self, gs: *gossip.GossipService) void {
        self.gossip_service = gs;
    }

    pub fn setLeaderSchedule(self: *Self, schedule: *consensus.leader_schedule.LeaderScheduleCache) void {
        self.leader_schedule = schedule;
    }

    pub fn setRpcUrl(self: *Self, url: []const u8) void {
        self.rpc_url = self.allocator.dupe(u8, url) catch return;
    }

    /// Override QUIC target address (local testing)
    pub fn setQuicTargetOverride(self: *Self, addr: packet.SocketAddr) void {
        self.quic_target_override = addr;
    }

    /// Update leader TPU address for a slot
    pub fn updateLeaderTpu(self: *Self, slot: core.Slot, addr: packet.SocketAddr) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.cacheLeaderTpuNoLock(slot, addr);
    }

    /// Get TPU address for current leader (Public with lock)
    pub fn getLeaderTpu(self: *Self, slot: core.Slot) ?packet.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getLeaderTpuNoLock(slot);
    }

    /// Internal non-locking TPU lookup
    fn getLeaderTpuNoLock(self: *Self, slot: core.Slot) ?packet.SocketAddr {
        // First check cache
        if (self.leader_tpu_cache.get(slot)) |addr| {
            if (self.isCacheFresh(self.leader_tpu_cache_ts.get(slot))) {
                return addr;
            }
            _ = self.leader_tpu_cache.remove(slot);
            _ = self.leader_tpu_cache_ts.remove(slot);
            self.stats.cache_refreshes += 1;
        }

        // Check negative cache — don't retry failed lookups within TTL
        if (self.failed_leader_lookups.get(slot)) |fail_ts| {
            const now = std.time.timestamp();
            if (now - fail_ts < LEADER_NEGATIVE_CACHE_TTL_SECS) {
                return null; // Still in cooldown, skip expensive lookup
            }
            // Expired — remove and try again
            _ = self.failed_leader_lookups.remove(slot);
        }

        // Try to look up leader TPU from gossip + leader schedule
        const leader_pubkey = self.getLeaderPubkey(slot);
        if (leader_pubkey) |lp| {
            if (self.gossip_service) |gs| {
                if (gs.table.getContact(lp)) |contact| {
                    const addr = contact.tpu_addr;
                    self.cacheLeaderTpuNoLock(slot, addr) catch {};
                    return addr;
                } else {
                    // Throttled: only log every 100th miss to avoid spam
                    self.leader_miss_count += 1;
                    if (self.leader_miss_count % 100 == 1) {
                        std.log.debug("[TPU] leader not in gossip (slot={d}, miss_count={d})\n", .{ slot, self.leader_miss_count });
                    }
                }
            } else {
                if (self.leader_miss_count % 100 == 1) {
                    std.log.debug("[TPU] gossip_service is null (slot={d})\n", .{slot});
                }
            }
        } else {
            self.leader_miss_count += 1;
            if (self.leader_miss_count % 100 == 1) {
                std.log.debug("[TPU] no leader pubkey (slot={d}, miss_count={d})\n", .{ slot, self.leader_miss_count });
            }
        }

        // Leader TPU resolution is GOSSIP-CANONICAL (Agave connection-cache /
        // Firedancer fd_txsend_tile resolve from gossip ContactInfo, not RPC).
        // The former RPC `getClusterNodes` fallback was removed here: it is
        // non-canonical AND it crashed (SIGABRT) on testnet — the multi-MB
        // getClusterNodes response overflowed the fixed 8KB std.Io.Writer buffer
        // inside std.http streaming (an uncatchable panic). On a gossip miss we
        // cache the negative result and let UDP carry the vote (FD liveness).

        // Cache this failure to avoid repeated expensive lookups
        self.failed_leader_lookups.put(slot, std.time.timestamp()) catch {};
        return null;
    }

    /// Get QUIC TPU address for current leader (Public with lock)
    pub fn getLeaderTpuQuic(self: *Self, slot: core.Slot) ?packet.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getLeaderTpuQuicNoLock(slot);
    }

    /// Internal non-locking QUIC TPU lookup
    fn getLeaderTpuQuicNoLock(self: *Self, slot: core.Slot) ?packet.SocketAddr {
        if (self.quic_target_override) |addr| {
            return addr;
        }
        if (self.leader_tpu_quic_cache.get(slot)) |addr| {
            if (self.isCacheFresh(self.leader_tpu_quic_cache_ts.get(slot))) {
                return addr;
            }
            _ = self.leader_tpu_quic_cache.remove(slot);
            _ = self.leader_tpu_quic_cache_ts.remove(slot);
            self.stats.cache_refreshes += 1;
        }

        // Resolve the leader's QUIC vote endpoint from gossip ContactInfo (canonical: Agave
        // connection-cache / FD fd_txsend_tile resolve leader TPU from gossip, never a per-vote RPC).
        // PREFER tag-8 tpu_quic — the LIVE QUIC TPU server that accepts votes. PROVEN 2026-06-18 by a
        // standalone real-leader handshake probe (src/vex_network/quic_leader_probe.zig): tag-8
        // (e.g. :8003 / :8002) completes the mTLS handshake on 12/16 leaders in 23-163ms, while the
        // advertised tag-12 tpu_vote_quic resolves to a NON-QUIC port on this cluster (Agave rc.0 gossip
        // exposes tpuQuic(tag8) + tpuVote(tag9 UDP) but no live tpu_vote_quic) and fails 0/5. FD txsend
        // also sends votes to tag-8 (conns[1]); Agave tpu(Protocol::QUIC)=tag-8. tag-12 is a SECONDARY,
        // used only when a leader advertises a real dedicated vote-QUIC port AND tag-8 is absent.
        const lp_opt = self.getLeaderPubkey(slot);
        if (lp_opt) |leader_pubkey| {
            if (self.gossip_service) |gs| {
                if (gs.table.getContact(leader_pubkey)) |contact| {
                    if (contact.tpu_quic_addr.port() != 0) {
                        const addr = contact.tpu_quic_addr;
                        self.cacheLeaderTpuQuicNoLock(slot, addr) catch {};
                        return addr;
                    }
                    if (contact.tpu_vote_quic_addr.port() != 0) {
                        const addr = contact.tpu_vote_quic_addr;
                        self.cacheLeaderTpuQuicNoLock(slot, addr) catch {};
                        return addr;
                    }
                }
            }
        }

        // No authoritative QUIC port in gossip for this leader → skip QUIC (UDP/curl carries the vote).
        // The former UDP+6 heuristic (udp_tpu_port + 6) was REMOVED 2026-06-18: real leaders advertise
        // QUIC on arbitrary ports (many with NO UDP TPU at all), so +6 fabricates a DEAD port — proven by
        // the real-leader handshake probe (tpuVote/+offset ports fail 0/5). Canonical: resolve QUIC from
        // gossip ContactInfo ONLY (Agave/FD), never fabricate a port from the UDP TPU socket.
        return null;
    }

    fn cacheLeaderTpuNoLock(self: *Self, slot: core.Slot, addr: packet.SocketAddr) !void {
        try self.leader_tpu_cache.put(slot, addr);
        try self.leader_tpu_cache_ts.put(slot, std.time.timestamp());
    }

    fn cacheLeaderTpuQuicNoLock(self: *Self, slot: core.Slot, addr: packet.SocketAddr) !void {
        try self.leader_tpu_quic_cache.put(slot, addr);
        try self.leader_tpu_quic_cache_ts.put(slot, std.time.timestamp());
    }

    fn isCacheFresh(self: *Self, ts: ?i64) bool {
        _ = self;
        const now = std.time.timestamp();
        return ts != null and (now - ts.?) <= LEADER_CACHE_TTL_SECS;
    }

    /// Get leader pubkey for a slot from leader schedule
    fn getLeaderPubkey(self: *Self, slot: core.Slot) ?core.Pubkey {
        if (self.leader_schedule) |schedule| {
            if (schedule.getSlotLeader(slot)) |leader| {
                return leader;
            }
        }
        return null;
    }

    /// Send a transaction to the current leader
    pub fn sendTransaction(self: *Self, tx_data: []const u8, target_slot: core.Slot, must_use_quic: bool) !void {
        if (tx_data.len > MAX_TX_SIZE) return error.TransactionTooLarge;

        const leader_addr = self.getLeaderTpu(target_slot) orelse {
            try self.queueTransaction(tx_data, target_slot);
            return;
        };

        if (self.enable_quic) {
            if (self.getLeaderTpuQuic(target_slot)) |quic_addr| {
                if (self.sendQuic(tx_data, quic_addr)) {
                    self.stats.txs_sent_quic += 1;
                    return;
                }
            } else if (self.force_quic) {
                try self.queueTransaction(tx_data, target_slot);
                return;
            }
        }

        if (must_use_quic) return error.QuicRequired;
        try self.sendUdp(tx_data, leader_addr);
        self.stats.txs_sent_udp += 1;
    }

    fn sendUdp(self: *Self, tx_data: []const u8, addr: packet.SocketAddr) !void {
        const sock = self.udp_socket orelse return error.NoSocket;
        const sockaddr = std.net.Address{ .in = .{ .sa = .{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, addr.port()),
            .addr = std.mem.nativeToBig(u32, (@as(u32, addr.addr[0]) << 24) | (@as(u32, addr.addr[1]) << 16) | (@as(u32, addr.addr[2]) << 8) | @as(u32, addr.addr[3])),
        } } };
        _ = try std.posix.sendto(sock, tx_data, 0, @ptrCast(&sockaddr.in.sa), @sizeOf(@TypeOf(sockaddr.in.sa)));
    }

    fn sendQuic(self: *Self, tx_data: []const u8, addr: packet.SocketAddr) bool {
        const quic_client = self.quic_client orelse return false;
        var ip_buf: [15]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3] }) catch return false;
        quic_client.sendTransaction(ip, addr.port(), tx_data) catch |err| {
            std.log.debug("[TPU-QUIC] Send failed to {s}:{d}: {}", .{ ip, addr.port(), err });
            return false;
        };
        return true;
    }

    pub fn queueTransaction(self: *Self, tx_data: []const u8, target_slot: core.Slot) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.pending_txs.items.len >= MAX_PENDING_TXS) {
            const oldest = self.pending_txs.orderedRemove(0);
            self.allocator.free(oldest.data);
            self.stats.txs_dropped += 1;
        }
        const data = try self.allocator.alloc(u8, tx_data.len);
        @memcpy(data, tx_data);
        try self.pending_txs.append(self.allocator, PendingTx{ .data = data, .target_slot = target_slot, .attempts = 0, .timestamp = std.time.timestamp(), .next_retry_at_ms = 0 });
    }

    /// Outcome of the vote-fanout QUIC pre-filter (2026-07-10 hygiene). Enqueued = a resolvable, live
    /// leader (goes into the pending ring, drained by processPending). The two skips do NOT enqueue —
    /// the UDP leg (main.zig VoteSender, unconditional) already carries the vote to that leader.
    pub const EnqueueResult = enum { enqueued, skipped_unresolvable, skipped_dead };

    /// Pure pre-filter DECISION: given the enqueue-time QUIC resolution result (`qaddr`, null when the
    /// leader has no usable gossip QUIC endpoint) and whether that endpoint is dead-cached, decide
    /// whether the vote should be QUIC-enqueued. RESOLVE-THEN-ENQUEUE (vs the old enqueue-then-resolve-
    /// in-poller that let unresolvable targets pollute the 256-deep ring). Pure ⟹ unit-testable without
    /// gossip/schedule/endpoint. Canonical: Agave/FD send only to leaders resolved from gossip
    /// ContactInfo (connection_cache.rs leader_updater; FD fd_txsend_tile.c), never to unknown targets.
    pub fn classifyEnqueue(qaddr: ?packet.SocketAddr, is_dead: bool) EnqueueResult {
        const addr = qaddr orelse return .skipped_unresolvable;
        _ = addr;
        if (is_dead) return .skipped_dead;
        return .enqueued;
    }

    /// True iff the resolved QUIC endpoint failed its handshake within the recent window (negative-
    /// endorsement memory owned by SolanaTpuQuic; reused, not duplicated). No quic_client ⟹ never dead.
    fn isTargetDead(self: *Self, addr: packet.SocketAddr) bool {
        const qc = self.quic_client orelse return false;
        var ip_buf: [15]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3] }) catch return false;
        return qc.isDeadCached(ip, addr.port());
    }

    /// Vote-fanout QUIC enqueue with pre-filter (2026-07-10). Resolves the leader's QUIC endpoint AT
    /// ENQUEUE TIME and enqueues into the pending ring ONLY for a resolvable, non-dead-cached leader;
    /// otherwise skips QUIC (the UDP leg already covers that leader) and bumps the matching counter.
    /// Replaces the old unconditional queueTransaction() in the fanout loop, which enqueued every
    /// target — including leaders with no gossip QUIC endpoint — so the ring filled with never-sendable
    /// entries that aged out as 'dropped' and delayed/starved QUIC sends for RESOLVABLE leaders.
    pub fn enqueueVote(self: *Self, vote_tx: []const u8, target_slot: core.Slot) EnqueueResult {
        const qaddr = self.getLeaderTpuQuic(target_slot);
        const is_dead = if (qaddr) |a| self.isTargetDead(a) else false;
        const decision = classifyEnqueue(qaddr, is_dead);
        switch (decision) {
            .enqueued => self.queueTransaction(vote_tx, target_slot) catch {
                // OOM / ring-append failure: treat as a skip (UDP already carried the vote). Do not
                // count it as unresolvable — it WAS resolvable; just don't claim it enqueued.
                return .skipped_unresolvable;
            },
            .skipped_unresolvable => self.stats.skipped_unresolvable += 1,
            .skipped_dead => self.stats.dead_cache_hits += 1,
        }
        return decision;
    }

    pub fn processPending(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var i: usize = 0;
        while (i < self.pending_txs.items.len) {
            const pending = &self.pending_txs.items[i];
            if (@as(u64, @intCast(std.time.milliTimestamp())) < pending.next_retry_at_ms) {
                i += 1;
                continue;
            }
            if (self.enable_quic) {
                if (self.getLeaderTpuQuicNoLock(pending.target_slot)) |qaddr| {
                    var batch: [MAX_TX_BATCH][]const u8 = undefined;
                    var idxs: [MAX_TX_BATCH]usize = undefined;
                    var count: usize = 0;
                    const desired = self.computeBatchSize();
                    var j: usize = i;
                    while (j < self.pending_txs.items.len and count < desired) : (j += 1) {
                        const item = &self.pending_txs.items[j];
                        const addr = self.getLeaderTpuQuicNoLock(item.target_slot) orelse continue;
                        if (addr.port() == qaddr.port() and std.mem.eql(u8, addr.addr[0..4], qaddr.addr[0..4])) {
                            batch[count] = item.data;
                            idxs[count] = j;
                            count += 1;
                        }
                    }
                    if (count > 0) {
                        const sent = self.sendQuicBatch(batch[0..count], qaddr);
                        if (sent > 0) {
                            // Count the QUIC sends. BUG FIX 2026-06-18: processPending (the poller's
                            // drain path) sent via QUIC but never incremented txs_sent_quic, so
                            // [QUIC-VOTE-STATS] read quic=0 even though votes were landing on every
                            // responsive leader (solana_quic.transactions_sent WAS counting them). The
                            // phantom quic=0 sent us chasing resolution/handshake bugs that were already
                            // fixed; the real defect was this missing counter.
                            self.stats.txs_sent_quic += sent;
                            self.stats.txs_sent_quic_batches += 1;
                            self.stats.txs_sent_quic_batched += sent;
                            var k: usize = count;
                            while (k > 0) {
                                k -= 1;
                                const idx = idxs[k];
                                self.allocator.free(self.pending_txs.items[idx].data);
                                _ = self.pending_txs.orderedRemove(idx);
                            }
                            continue;
                        }
                    }
                }
            }
            // This item was NOT sent or removed this pass (no QUIC leader resolved, QUIC
            // disabled, or sendQuicBatch returned 0). No orderedRemove ran in this iteration —
            // the only removal path (sent > 0) `continue`s above — so `pending` (= &items[i])
            // is still valid at index i. Stamp the existing-but-never-set backoff so the next
            // ~1ms processPending pass SKIPS it (line above) instead of re-resolving the leader
            // for it ~1000x/sec. The not-yet-due skip path above is NOT re-stamped (it already
            // holds a future stamp), so a backed-off vote is not pushed further out every pass.
            pending.next_retry_at_ms = @as(u64, @intCast(std.time.milliTimestamp())) + RETRY_BACKOFF_MS;
            i += 1;
        }
    }

    /// Snapshot diagnostic (called ~every 10s by the vote poller, NOT on the hot path): classify the
    /// current pending-vote backlog so we can tell WHY votes aren't draining — unresolved leader
    /// (gossip/schedule gap) vs connection not-yet-handshake-complete (warmth, what prewarm targets)
    /// vs ready-to-drain-this-round. Lock order TpuClient.mutex → SolanaTpuQuic.mutex matches
    /// processPending (no deadlock).
    pub fn pendingDiag(self: *Self) struct { depth: usize, unresolved: usize, not_ready: usize, ready: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();
        var unresolved: usize = 0;
        var not_ready: usize = 0;
        var ready: usize = 0;
        for (self.pending_txs.items) |pending| {
            const qaddr = self.getLeaderTpuQuicNoLock(pending.target_slot) orelse {
                unresolved += 1;
                continue;
            };
            const qc = self.quic_client orelse {
                not_ready += 1;
                continue;
            };
            var ip_buf: [15]u8 = undefined;
            const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ qaddr.addr[0], qaddr.addr[1], qaddr.addr[2], qaddr.addr[3] }) catch {
                not_ready += 1;
                continue;
            };
            if (qc.isReadyNonBlocking(ip, qaddr.port())) ready += 1 else not_ready += 1;
        }
        return .{ .depth = self.pending_txs.items.len, .unresolved = unresolved, .not_ready = not_ready, .ready = ready };
    }

    fn computeBatchSize(self: *Self) usize {
        if (self.quic_batch_size_override > 0) return self.quic_batch_size_override;
        return self.quic_batch_auto_cap;
    }

    fn sendQuicBatch(self: *Self, txs: [][]const u8, addr: packet.SocketAddr) usize {
        const quic_client = self.quic_client orelse return 0;
        var ip_buf: [15]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3] }) catch return 0;
        // NON-BLOCKING: processPending holds the TpuClient mutex, which is on the replay thread's vote
        // path (queueTransaction). The old blocking coalesced send (getOrConnect → waitForHandshake, ≤5s)
        // held the mutex across a QUIC handshake and stalled replay → catch-up stall (2026-06-18). The
        // non-blocking variant returns 0 (tx stays queued, retried next round) until the connection's
        // handshake — driven by poll() — completes. Canonical Agave async-warmup model.
        return quic_client.sendTransactionBatchCoalescedNonBlocking(ip, addr.port(), txs);
    }

    pub fn sendVote(self: *Self, vote_tx: []const u8, target_slot: core.Slot) !void {
        // Next 3 leaders (Agave FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET=2 → fanout 3;
        // Firedancer txsend next-3 rotations). Widened from 2 to match canonical landing coverage.
        const slots_to_try = [_]core.Slot{ target_slot, target_slot + 1, target_slot + 2 };
        var sent_count: u32 = 0;
        for (slots_to_try) |slot| {
            if (self.enable_quic) {
                if (self.getLeaderTpuQuic(slot)) |qaddr| {
                    if (self.sendQuic(vote_tx, qaddr)) {
                        sent_count += 1;
                        self.stats.txs_sent_quic += 1;
                    }
                }
            }
            if (!self.force_quic) {
                if (self.getLeaderTpu(slot)) |addr| {
                    try self.sendUdp(vote_tx, addr);
                    sent_count += 1;
                    self.stats.txs_sent_udp += 1;
                }
            }
        }
        if (sent_count == 0) {
            try self.queueTransaction(vote_tx, target_slot);
            return error.VoteQueued;
        }
    }

    /// Pre-open QUIC connections to the next `count` upcoming leaders so their handshakes complete
    /// BEFORE their slots arrive (canonical Agave connect-ahead / Firedancer txsend pre-open). The
    /// per-leader handshake (~1 RTT after the coalescing fix) then never lands on a vote's critical
    /// path. Non-blocking — SolanaTpuQuic.prewarm just initiates the connection; the QUIC drive
    /// thread's poll() completes it. MUST be called from the QUIC drive thread (the endpoint owner).
    pub fn prewarmUpcoming(self: *Self, current_slot: core.Slot, count: u8) void {
        const qc = self.quic_client orelse return;
        var i: u8 = 0;
        while (i < count) : (i += 1) {
            const addr = self.getLeaderTpuQuic(current_slot + i) orelse continue;
            var ip_buf: [16]u8 = undefined;
            const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3] }) catch continue;
            qc.prewarm(ip, addr.port());
        }
    }
};

// ── KAT: processPending retry-backoff (RETRY_BACKOFF_MS wire-up, 2026-06-29) ───────────────────
// Proves the dead next_retry_at_ms field is now actually stamped, so the QUIC poller no longer
// re-resolves the leader for an un-sendable vote ~1000x/sec (the O(N²)/~40%-CPU defect). With no
// quic_client, no leader_schedule and no gossip, getLeaderTpuQuicNoLock returns null → every queued
// vote takes the un-sent path → must get a backoff stamp; a second immediate pass must SKIP them all.
test "processPending stamps RETRY_BACKOFF_MS and a second immediate pass skips un-sent votes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // enable_quic=true so processPending walks the QUIC path; quic_client stays null and no
    // leader resolves → sends never succeed → items stay pending and take the backoff path.
    const client = try TpuClient.init(allocator, true, true, false, true, 0, true, 8010);
    defer client.deinit();

    const K: usize = 4;
    const dummy = [_]u8{0xAB} ** 64; // any non-empty payload; never actually sent
    var s: u64 = 0;
    while (s < K) : (s += 1) {
        try client.queueTransaction(&dummy, 100 + s);
    }
    try testing.expectEqual(K, client.pending_txs.items.len);

    // Fresh votes attempt immediately (no backoff yet).
    for (client.pending_txs.items) |p| {
        try testing.expectEqual(@as(u64, 0), p.next_retry_at_ms);
    }

    // First pass: nothing can be sent (no leader) → every item gets a future backoff stamp,
    // and none are removed.
    client.processPending();
    try testing.expectEqual(K, client.pending_txs.items.len);
    var stamps: [K]u64 = undefined;
    for (client.pending_txs.items, 0..) |p, idx| {
        try testing.expect(p.next_retry_at_ms > 0);
        stamps[idx] = p.next_retry_at_ms;
    }

    // Second immediate pass (same ~ms, well within RETRY_BACKOFF_MS): every item is not-yet-due,
    // so processPending must SKIP it — depth unchanged AND stamps unchanged. If it had re-attempted
    // (re-resolving the leader), it would have written a new, larger stamp. Unchanged == skipped.
    client.processPending();
    try testing.expectEqual(K, client.pending_txs.items.len);
    for (client.pending_txs.items, 0..) |p, idx| {
        try testing.expectEqual(stamps[idx], p.next_retry_at_ms);
    }

    // Simulate backoff expiry (we cannot move the real clock): clear the stamps → the next pass
    // must re-attempt and therefore re-stamp every still-un-sendable item.
    for (client.pending_txs.items) |*p| p.next_retry_at_ms = 0;
    client.processPending();
    try testing.expectEqual(K, client.pending_txs.items.len);
    for (client.pending_txs.items) |p| {
        try testing.expect(p.next_retry_at_ms > 0);
    }

    // A brand-new vote is still queued with next_retry_at_ms==0 → it attempts on the very next pass
    // (queueTransaction is unchanged; the backoff only delays RE-attempts of an un-sendable vote).
    try client.queueTransaction(&dummy, 999);
    try testing.expectEqual(@as(u64, 0), client.pending_txs.items[client.pending_txs.items.len - 1].next_retry_at_ms);
}

// ── KAT: vote-fanout QUIC pre-filter DECISION (classifyEnqueue, 2026-07-10) ──────────────────────
// Proves the pure resolve-then-enqueue decision: a resolvable+live leader enqueues; an unresolvable
// leader (no gossip QUIC endpoint) is skipped as unresolvable; a resolvable-but-dead-cached leader is
// skipped as dead. This is the correctness core of the ring-pollution fix (the enqueue itself and the
// live gossip/dead-cache lookups are exercised by enqueueVote + the solana_quic isDeadTarget KAT).
test "classifyEnqueue: resolvable→enqueued, unresolvable→skipped, dead-cached→skipped" {
    const testing = std.testing;
    const addr = packet.SocketAddr.ipv4(.{ 10, 0, 0, 7 }, 8010);

    // resolvable + not dead → enqueue
    try testing.expectEqual(TpuClient.EnqueueResult.enqueued, TpuClient.classifyEnqueue(addr, false));
    // unresolvable (no gossip QUIC endpoint) → skip, regardless of dead flag
    try testing.expectEqual(TpuClient.EnqueueResult.skipped_unresolvable, TpuClient.classifyEnqueue(null, false));
    try testing.expectEqual(TpuClient.EnqueueResult.skipped_unresolvable, TpuClient.classifyEnqueue(null, true));
    // resolvable but recently dead-cached → skip (UDP still carries it)
    try testing.expectEqual(TpuClient.EnqueueResult.skipped_dead, TpuClient.classifyEnqueue(addr, true));
}

// ── KAT: enqueueVote integration (resolvable enqueues + counts, unresolvable skips + counts) ─────
// Drives the real enqueueVote against a TpuClient with no gossip/schedule. With a quic_target_override
// set, getLeaderTpuQuic resolves for EVERY slot → the vote is enqueued into the ring and no skip
// counter moves. With the override cleared and no gossip/schedule, resolution fails → the vote is NOT
// enqueued (ring stays empty) and skipped_unresolvable is counted. quic_client stays null so
// isTargetDead is a safe no-op (never-dead) — the dead path's decision is covered by classifyEnqueue.
test "enqueueVote: resolvable→ring+enqueued, unresolvable→skipped_unresolvable counted, no ring growth" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const client = try TpuClient.init(allocator, true, true, false, true, 0, true, 8010);
    defer client.deinit();
    const dummy = [_]u8{0xCD} ** 48;

    // Force resolution for any slot via the local-testing override.
    client.setQuicTargetOverride(packet.SocketAddr.ipv4(.{ 10, 0, 0, 7 }, 8010));
    try testing.expectEqual(TpuClient.EnqueueResult.enqueued, client.enqueueVote(&dummy, 100));
    try testing.expectEqual(@as(usize, 1), client.pending_txs.items.len);
    try testing.expectEqual(@as(u64, 0), client.stats.skipped_unresolvable);
    try testing.expectEqual(@as(u64, 0), client.stats.dead_cache_hits);

    // Clear the override → no gossip, no schedule → resolution fails → skip, do NOT touch the ring.
    client.quic_target_override = null;
    try testing.expectEqual(TpuClient.EnqueueResult.skipped_unresolvable, client.enqueueVote(&dummy, 200));
    try testing.expectEqual(@as(usize, 1), client.pending_txs.items.len); // unchanged
    try testing.expectEqual(@as(u64, 1), client.stats.skipped_unresolvable);
    try testing.expectEqual(@as(u64, 0), client.stats.dead_cache_hits);
}
