//! Vexor Leader Schedule
//!
//! Calculates and caches the leader schedule for each epoch.
//! The schedule is deterministically derived from stake weights.
//!
//! Schedule determination:
//! 1. Get stake weights at epoch boundary
//! 2. Shuffle validators using epoch-seeded RNG
//! 3. Assign slots proportionally to stake

const std = @import("std");
const core = @import("core");
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Pubkey = core.Pubkey;
const Slot = core.Slot;
const Epoch = core.Epoch;

/// Stake weight entry
pub const StakeWeight = struct {
    pubkey: Pubkey,
    stake: u64,
};

/// Leader schedule for an epoch
pub const EpochSchedule = struct {
    epoch: Epoch,
    first_slot: Slot,
    last_slot: Slot,
    slot_leaders: []Pubkey,

    pub fn deinit(self: *EpochSchedule, allocator: Allocator) void {
        allocator.free(self.slot_leaders);
    }

    /// Get leader for a slot
    pub fn getLeader(self: *const EpochSchedule, slot: Slot) ?Pubkey {
        if (slot < self.first_slot or slot > self.last_slot) return null;
        const idx = slot - self.first_slot;
        if (idx >= self.slot_leaders.len) return null;
        return self.slot_leaders[idx];
    }

    /// Check if pubkey is leader for slot
    pub fn isLeader(self: *const EpochSchedule, slot: Slot, pubkey: Pubkey) bool {
        if (self.getLeader(slot)) |leader| {
            return std.mem.eql(u8, &leader.data, &pubkey.data);
        }
        return false;
    }

    /// Get slots where pubkey is leader
    pub fn getLeaderSlots(self: *const EpochSchedule, pubkey: Pubkey, allocator: Allocator) ![]Slot {
        var slots = std.ArrayListUnmanaged(Slot){};

        for (self.slot_leaders, 0..) |leader, idx| {
            if (std.mem.eql(u8, &leader.data, &pubkey.data)) {
                try slots.append(allocator, self.first_slot + idx);
            }
        }

        return slots.toOwnedSlice(allocator);
    }
};

/// Leader schedule generator
pub const LeaderScheduleGenerator = struct {
    allocator: Allocator,
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    first_normal_epoch: u64,
    first_normal_slot: u64,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .slots_per_epoch = 432000,
            .leader_schedule_slot_offset = 432000,
            .first_normal_epoch = 14,
            .first_normal_slot = 524256, // Correct testnet value (verified from getEpochSchedule RPC)
        };
    }

    /// Get epoch for slot (warmup-aware)
    pub fn getEpoch(self: *const Self, slot: Slot) Epoch {
        if (slot >= self.first_normal_slot) {
            return self.first_normal_epoch + (slot - self.first_normal_slot) / self.slots_per_epoch;
        }
        // Warmup phase
        const MINIMUM_SLOTS: u64 = 32;
        var epoch_len: u64 = MINIMUM_SLOTS;
        var epoch: u64 = 0;
        var slot_count: u64 = 0;
        while (slot_count + epoch_len <= slot and epoch < self.first_normal_epoch) {
            slot_count += epoch_len;
            epoch += 1;
            epoch_len *|= 2;
        }
        return epoch;
    }

    /// Get first slot of epoch (warmup-aware)
    pub fn getFirstSlotInEpoch(self: *const Self, epoch: Epoch) Slot {
        if (epoch >= self.first_normal_epoch) {
            return self.first_normal_slot + (epoch - self.first_normal_epoch) * self.slots_per_epoch;
        }
        const MINIMUM_SLOTS: u64 = 32;
        var slot_count: u64 = 0;
        var e: u64 = 0;
        var epoch_len: u64 = MINIMUM_SLOTS;
        while (e < epoch) {
            slot_count += epoch_len;
            e += 1;
            epoch_len *|= 2;
        }
        return slot_count;
    }

    /// Get last slot of epoch
    pub fn getLastSlotInEpoch(self: *const Self, epoch: Epoch) Slot {
        return self.getFirstSlotInEpoch(epoch + 1) - 1;
    }
};

/// Leader schedule cache
pub const LeaderScheduleCache = struct {
    allocator: Allocator,
    schedules: std.AutoHashMap(Epoch, EpochSchedule),
    mutex: Mutex,
    generator: LeaderScheduleGenerator,

    /// Per-epoch node-identity → stake, retained ONLY for repair-peer
    /// stake-weighting (NON-CONSENSUS liveness; see tvu.getRepairPeers, gated
    /// -Drepair_stake_weighting). This is the SAME node→stake data
    /// populateAgaveCanonical already derives in `stakes_buf` (leader.id =
    /// node_pubkey, .stake), kept in lockstep with `schedules` (populated +
    /// evicted together) so a stake-weighted repair lookup needs no live
    /// AccountsDb read. Epochs cached via addSchedule directly (not the
    /// live populate path) simply have no entry here → fillStakesForSlot returns
    /// all-zero → repair gracefully degrades to round-robin. Never feeds
    /// bank_hash/vote/consensus. Guarded by `mutex`.
    epoch_stakes: std.AutoHashMap(Epoch, std.AutoHashMapUnmanaged([32]u8, u64)),

    /// Our identity (for checking if we're leader)
    identity: ?Pubkey = null,

    /// Current slot estimate (updated by replay stage for vote leader targeting)
    current_slot_estimate: u64 = 0,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .schedules = std.AutoHashMap(Epoch, EpochSchedule).init(allocator),
            .mutex = .{},
            .generator = LeaderScheduleGenerator.init(allocator),
            .identity = null,
            .epoch_stakes = std.AutoHashMap(Epoch, std.AutoHashMapUnmanaged([32]u8, u64)).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.schedules.valueIterator();
        while (iter.next()) |schedule| {
            var s = schedule.*;
            s.deinit(self.allocator);
        }
        self.schedules.deinit();

        // Free the retained per-epoch node→stake maps (repair stake-weighting).
        var st_iter = self.epoch_stakes.valueIterator();
        while (st_iter.next()) |m| m.deinit(self.allocator);
        self.epoch_stakes.deinit();
    }

    /// Fill `weights_out[i]` with the cached epoch stake of node identity
    /// `nodes[i]` for the epoch containing `slot` (0 for unknown nodes, or if no
    /// stakes are cached for that epoch). REPAIR-PEER stake-weighting ONLY
    /// (non-consensus liveness) — never feeds bank_hash/vote/consensus. Locked
    /// copy-out: no aliased map pointer escapes `mutex`, so an epoch-boundary
    /// populate (which frees/replaces the inner map) cannot UAF the caller.
    /// `nodes` and `weights_out` must have equal length.
    pub fn fillStakesForSlot(self: *Self, slot: Slot, nodes: []const [32]u8, weights_out: []u64) void {
        std.debug.assert(nodes.len == weights_out.len);
        const epoch = self.generator.getEpoch(slot);
        self.mutex.lock();
        defer self.mutex.unlock();
        @memset(weights_out, 0);
        const m = self.epoch_stakes.getPtr(epoch) orelse return;
        for (nodes, weights_out) |nk, *w| {
            w.* = m.get(nk) orelse 0;
        }
    }

    /// Copy the FULL epoch staked-node map (node_identity -> stake) for `slot`'s
    /// epoch into `out` (cleared first). Same mutex-safe copy-out discipline as
    /// fillStakesForSlot: no aliased inner-map pointer escapes `mutex`, so an
    /// epoch-boundary populate (which frees/replaces the inner map) cannot UAF.
    ///
    /// Returns the number of staked nodes copied. 0 means the epoch is NOT yet
    /// populated (only populateAgaveCanonical fills epoch_stakes; epochs cached
    /// via addSchedule directly have no entry) — callers MUST treat 0 as "no real
    /// stakes available" and fall back, never as "an unstaked cluster".
    ///
    /// LIVENESS-only consumer (turbine broadcast/retransmit tree); never feeds
    /// bank_hash/vote/consensus. Keyed by NODE IDENTITY (the gossip/TVU pubkey),
    /// @prov:leader-schedule.epoch-stakes-keying — same keying as upstream's stake map.
    pub fn copyEpochStakes(self: *Self, slot: Slot, out: *std.AutoHashMap([32]u8, u64)) usize {
        const epoch = self.generator.getEpoch(slot);
        self.mutex.lock();
        defer self.mutex.unlock();
        out.clearRetainingCapacity();
        const m = self.epoch_stakes.getPtr(epoch) orelse return 0;
        var it = m.iterator();
        var n: usize = 0;
        while (it.next()) |e| {
            out.put(e.key_ptr.*, e.value_ptr.*) catch continue;
            n += 1;
        }
        return n;
    }

    /// Get leader for slot
    pub fn getSlotLeader(self: *Self, slot: Slot) ?Pubkey {
        self.mutex.lock();
        defer self.mutex.unlock();

        const epoch = self.generator.getEpoch(slot);
        const count = self.schedules.count();
        if (self.schedules.get(epoch)) |schedule| {
            // Gate noisy print: only first 5 calls and every 10000th
            const S = struct {
                var call_count: u64 = 0;
            };
            S.call_count += 1;
            if (S.call_count <= 5 or S.call_count % 10000 == 0) {
                std.log.debug("[LS] slot={d} epoch={d} count={d} first={d} last={d}\n", .{ slot, epoch, count, schedule.first_slot, schedule.last_slot });
            }
            return schedule.getLeader(slot);
        }
        // Gate "NO SCHEDULE" print to avoid spam on epoch boundary
        const NS = struct {
            var miss_count: u64 = 0;
        };
        NS.miss_count += 1;
        if (NS.miss_count <= 5 or NS.miss_count % 1000 == 0) {
            std.log.debug("[LS] NO SCHEDULE: slot={d} epoch={d} count={d} miss#{d}\n", .{ slot, epoch, count, NS.miss_count });
        }
        return null;
    }

    /// Add schedule for epoch
    pub fn addSchedule(self: *Self, schedule: EpochSchedule) !void {
        std.log.debug("[LS] addSchedule: epoch={d} first={d} last={d} leaders_len={d}\n", .{ schedule.epoch, schedule.first_slot, schedule.last_slot, schedule.slot_leaders.len });
        self.mutex.lock();
        defer self.mutex.unlock();

        // Remove old schedule if exists
        if (self.schedules.fetchRemove(schedule.epoch)) |removed| {
            var s = removed.value;
            s.deinit(self.allocator);
        }

        try self.schedules.put(schedule.epoch, schedule);
    }

    /// @prov:leader-schedule.populate-pipeline — d28ff (2026-05-12): populate
    /// cache using the canonical port (no RPC). Pipeline:
    ///   1. Look up `accounts_db.epoch_stakes` for the current epoch
    ///      (snapshot-frozen vote_account stake table).
    ///   2. For each (vote_pubkey, stake) with stake > 0: load the vote
    ///      account from AccountsDb, extract `node_pubkey` (32 bytes
    ///      starting at offset 4 — after the u32 version prefix).
    ///   3. Build `[]SlotLeaderStake` and call `LeaderSchedule.init` from
    ///      `leader_schedule_agave.zig` — which performs sort by stake DESC
    ///      (tiebreak: vote_address DESC), dedup, prefix sum, then
    ///      WeightedU64Index alias-sampling under ChaChaRng(epoch) with
    ///      NUM_CONSECUTIVE_LEADER_SLOTS = 4. Byte-equivalent to govnode's
    ///      `getLeaderSchedule` RPC response.
    ///   4. Convert to legacy `EpochSchedule { slot_leaders: []Pubkey }`
    ///      so the existing `getSlotLeader` consumer path is unchanged.
    ///
    /// `accounts_db` is taken as `anytype` to avoid an import cycle
    /// (vex_consensus has no dep on vex_store at module boundary).
    pub fn populateAgaveCanonical(
        self: *Self,
        accounts_db: anytype,
        current_slot: Slot,
    ) !void {
        const agave = @import("leader_schedule_agave.zig");

        const current_epoch = self.generator.getEpoch(current_slot);

        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.schedules.contains(current_epoch)) return;

        // 1. Find epoch_stakes entry for current_epoch.
        var found_stakes: ?[]const @TypeOf(accounts_db.epoch_stakes[0].vote_account_stakes[0]) = null;
        var found_node_pks: []const [32]u8 = &[_][32]u8{};
        for (accounts_db.epoch_stakes) |entry| {
            if (entry.epoch == current_epoch) {
                found_stakes = entry.vote_account_stakes;
                found_node_pks = entry.node_pubkeys;
                break;
            }
        }
        const epoch_stakes = found_stakes orelse {
            std.log.warn("[LeaderSchedule] populateAgaveCanonical: no epoch_stakes for epoch {d} (have {d} epochs cached)", .{ current_epoch, accounts_db.epoch_stakes.len });
            return error.NoEpochStakes;
        };
        const node_pks_parallel = found_node_pks;

        // 2. Build SlotLeaderStake[] using the node_pubkey captured at snapshot
        //    parse time (frozen vote_account.data[4..36] inside the snapshot's
        //    versioned_epoch_stakes blob). Mirrors Agave's
        //    `vote_account.node_pubkey()` which reads from the SNAPSHOTTED
        //    vote_account, NOT live AccountsDb. d28zz fix: previously this
        //    function looked up live AccountsDb which produced missing_acct>0
        //    when a vote account in epoch_stakes wasn't present in the live db
        //    yet (cold cache / mmap miss). One missing validator drops 1500+
        //    slots that then get redistributed by stake weight, putting the
        //    wrong leader in those slots — drives bank_hash divergence at every
        //    slot whose leader changed.
        var stakes_buf = try self.allocator.alloc(agave.SlotLeaderStake, epoch_stakes.len);
        defer self.allocator.free(stakes_buf);
        var n_built: usize = 0;
        var missing_account: usize = 0;
        var bad_data: usize = 0;
        var node_pk_zero: usize = 0;
        var fallback_db: usize = 0;
        for (epoch_stakes, 0..) |vs, i| {
            if (vs.stake == 0) continue;
            var node_pubkey: [32]u8 = if (i < node_pks_parallel.len) node_pks_parallel[i] else [_]u8{0} ** 32;
            const captured = !std.mem.eql(u8, &node_pubkey, &([_]u8{0} ** 32));
            if (!captured) {
                // Snapshot didn't capture node_pubkey (older snapshot blob or
                // empty data). Fall back to live AccountsDb — same path as
                // before d28zz; counts gap so we can monitor.
                node_pk_zero += 1;
                const vote_pk = Pubkey{ .data = vs.vote_pubkey };
                const acct_opt = accounts_db._getRooted(&vote_pk);
                const acct = acct_opt orelse {
                    missing_account += 1;
                    continue;
                };
                if (acct.data.len < 36) {
                    bad_data += 1;
                    continue;
                }
                @memcpy(&node_pubkey, acct.data[4..36]);
                fallback_db += 1;
            }
            stakes_buf[n_built] = .{
                .leader = .{ .id = node_pubkey, .vote_address = vs.vote_pubkey },
                .stake = vs.stake,
            };
            n_built += 1;
        }

        if (n_built == 0) {
            std.log.warn("[LeaderSchedule] populateAgaveCanonical: 0 vote accounts resolved (epoch_stakes={d}, missing={d}, bad_data={d})", .{ epoch_stakes.len, missing_account, bad_data });
            return error.NoStake;
        }
        std.log.warn("[LeaderSchedule] Agave-canonical compute: epoch={d} resolved={d} missing_acct={d} bad_data={d} node_pk_zero={d} fallback_db={d}", .{ current_epoch, n_built, missing_account, bad_data, node_pk_zero, fallback_db });

        // 3. Compute schedule.
        const slots_per_epoch = self.generator.slots_per_epoch;
        var schedule = try agave.LeaderSchedule.init(
            self.allocator,
            stakes_buf[0..n_built],
            current_epoch,
            slots_per_epoch,
            agave.NUM_CONSECUTIVE_LEADER_SLOTS,
        );
        defer schedule.deinit();

        // 4. Convert to legacy EpochSchedule. Owned by the cache after addSchedule.
        const slot_leaders_pk = try self.allocator.alloc(Pubkey, schedule.slot_leaders.len);
        errdefer self.allocator.free(slot_leaders_pk);
        for (schedule.slot_leaders, 0..) |sl, i| {
            slot_leaders_pk[i] = Pubkey{ .data = sl.id };
        }

        const first_slot = self.generator.getFirstSlotInEpoch(current_epoch);
        const epoch_schedule = EpochSchedule{
            .epoch = current_epoch,
            .first_slot = first_slot,
            .last_slot = first_slot + slot_leaders_pk.len - 1,
            .slot_leaders = slot_leaders_pk,
        };

        // Inline of addSchedule (we already hold the mutex).
        if (self.schedules.fetchRemove(epoch_schedule.epoch)) |removed| {
            var s = removed.value;
            s.deinit(self.allocator);
        }
        try self.schedules.put(epoch_schedule.epoch, epoch_schedule);

        // Retain node→stake for repair-peer stake-weighting (NON-CONSENSUS
        // liveness; see fillStakesForSlot). BEST-EFFORT and NON-FATAL: the schedule
        // is ALREADY cached above, so this auxiliary map must never change whether
        // populateAgaveCanonical succeeds — any alloc failure here frees the partial
        // map and we proceed (repair degrades to round-robin for this epoch). This
        // keeps schedule-population behavior byte-identical to pre-change. Reuses the
        // SAME node→stake data already in `stakes_buf` (leader.id = node identity,
        // .stake), summed per node (one node may run multiple vote accounts). Kept
        // in lockstep with `schedules`; stale entry evicted first.
        {
            var stake_map: std.AutoHashMapUnmanaged([32]u8, u64) = .{};
            var stored = false;
            defer if (!stored) stake_map.deinit(self.allocator);
            const built = blk: {
                for (stakes_buf[0..n_built]) |ss| {
                    const gop = stake_map.getOrPut(self.allocator, ss.leader.id) catch break :blk false;
                    gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + ss.stake else ss.stake;
                }
                if (self.epoch_stakes.fetchRemove(current_epoch)) |old| {
                    var m = old.value;
                    m.deinit(self.allocator);
                }
                self.epoch_stakes.put(current_epoch, stake_map) catch break :blk false;
                break :blk true;
            };
            stored = built;
            if (!built) std.log.warn("[LeaderSchedule] repair stake-map retain skipped (alloc) epoch={d}", .{current_epoch});
        }

        std.log.warn("[LeaderSchedule] Agave-canonical schedule cached: epoch={d} first_slot={d} last_slot={d} num_leaders={d}", .{
            current_epoch, first_slot, first_slot + slot_leaders_pk.len - 1, slot_leaders_pk.len,
        });

        // d28yy diag: dump a slice of the computed schedule + top-5 stakes so we
        // can compare to cluster's getLeaderSchedule. Remove once carrier-2
        // (leader-credit drift) is closed.
        {
            // Top-5 highest-stake input validators (post-sort done inside agave.LeaderSchedule.init).
            var top5_idx: [5]usize = .{ 0, 0, 0, 0, 0 };
            var top5_stk: [5]u64 = .{ 0, 0, 0, 0, 0 };
            for (stakes_buf[0..n_built], 0..) |ss, i| {
                var slot_idx: usize = 5;
                for (top5_stk, 0..) |s, j| {
                    if (ss.stake > s) {
                        slot_idx = j;
                        break;
                    }
                }
                if (slot_idx < 5) {
                    var k: usize = 4;
                    while (k > slot_idx) : (k -= 1) {
                        top5_stk[k] = top5_stk[k - 1];
                        top5_idx[k] = top5_idx[k - 1];
                    }
                    top5_stk[slot_idx] = ss.stake;
                    top5_idx[slot_idx] = i;
                }
            }
            for (top5_idx, top5_stk, 0..) |i, s, rank| {
                if (s == 0) continue;
                const sl = stakes_buf[i];
                std.log.warn("[d28yy-LS-DIAG] top{d} stake={d} vote=0x{x:0>8} node=0x{x:0>8}", .{
                    rank,                                                        s,
                    std.mem.readInt(u32, sl.leader.vote_address[0..4], .little), std.mem.readInt(u32, sl.leader.id[0..4], .little),
                });
            }

            // Dump leaders for slot indices around 154976..154985 (slot 408055232..408055241 in epoch 957).
            const DIAG_START: usize = 154976;
            const DIAG_END: usize = 154985;
            if (slot_leaders_pk.len > DIAG_END) {
                var ii: usize = DIAG_START;
                while (ii <= DIAG_END) : (ii += 1) {
                    const pk = slot_leaders_pk[ii];
                    std.log.warn("[d28yy-LS-DIAG] idx={d} slot={d} leader_first8=0x{x:0>16}", .{
                        ii,                                           first_slot + ii,
                        std.mem.readInt(u64, pk.data[0..8], .little),
                    });
                }
            }

            // Also: total stake + n_built.
            var total_stake: u64 = 0;
            for (stakes_buf[0..n_built]) |ss| total_stake +%= ss.stake;
            std.log.warn("[d28yy-LS-DIAG] epoch={d} total_stake={d} n_built={d}", .{ current_epoch, total_stake, n_built });
        }
    }

    /// Check if we're leader for slot
    pub fn isLeader(self: *Self, slot: Slot, pubkey: Pubkey) bool {
        if (self.getSlotLeader(slot)) |leader| {
            return std.mem.eql(u8, &leader.data, &pubkey.data);
        }
        return false;
    }

    /// Get leader slots for a specific pubkey in an epoch
    pub fn getLeaderSlots(self: *Self, pubkey: Pubkey, epoch: Epoch, allocator: Allocator) ![]Slot {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.schedules.get(epoch)) |schedule| {
            return schedule.getLeaderSlots(pubkey, allocator);
        }
        return allocator.alloc(Slot, 0);
    }

    /// Fetch leader schedule from RPC endpoint
    /// @prov:leader-schedule.fetch-rpc
    /// NOTE: Using curl subprocess because Zig std.http.Client doesn't properly send Content-Type header
    pub fn fetchFromRpc(self: *Self, rpc_url: []const u8, slot: ?Slot) !void {
        std.log.debug("[LeaderSchedule] Fetching from RPC: {s} for slot {?d}\n", .{ rpc_url, slot });

        // Build JSON-RPC request body
        const request_body = if (slot) |s|
            try std.fmt.allocPrint(self.allocator, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLeaderSchedule\",\"params\":[{d}]}}", .{s})
        else
            try std.fmt.allocPrint(self.allocator, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLeaderSchedule\",\"params\":[]}}", .{});
        defer self.allocator.free(request_body);

        // Build shell command string for curl
        const curl_cmd = try std.fmt.allocPrint(self.allocator, "/usr/bin/curl -s -X POST -H 'Content-Type: application/json' -d '{s}' {s}", .{ request_body, rpc_url });
        defer self.allocator.free(curl_cmd);

        std.log.debug("[LeaderSchedule] Fetching leader schedule via curl...\n", .{});

        // Use shell to execute curl command
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "/bin/sh",
                "-c",
                curl_cmd,
            },
            .max_output_bytes = 100 * 1024 * 1024, // Leader schedule can be several MB
        }) catch |err| {
            std.log.debug("[LeaderSchedule] curl failed: {}\n", .{err});
            return err;
        };
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        const response = result.stdout;
        std.log.debug("[LeaderSchedule] Response length: {d} bytes\n", .{response.len});
        if (response.len < 500) {
            std.log.debug("[LeaderSchedule] Response: {s}\n", .{response});
        } else {
            std.log.debug("[LeaderSchedule] Response (truncated): {s}...\n", .{response[0..500]});
        }

        // Check for RPC error or null result
        if (std.mem.indexOf(u8, response, "\"error\"")) |_| {
            std.log.debug("[LeaderSchedule] RPC returned error!\n", .{});
            return error.RpcError;
        }

        if (std.mem.indexOf(u8, response, "\"result\":null")) |_| {
            std.log.info("[LeaderSchedule] RPC returned null result for slot {?d} (schedule not available yet)", .{slot});
            return error.RpcError;
        }

        // When slot is null, getLeaderSchedule returns current epoch's schedule.
        // We need to know the current slot to compute the correct epoch.
        var effective_slot = slot orelse blk: {
            // Fetch current slot from RPC to determine the right epoch
            const getslot_cmd = std.fmt.allocPrint(self.allocator, "/usr/bin/curl -s -X POST -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSlot\"}}' {s}", .{rpc_url}) catch break :blk @as(u64, 0);
            defer self.allocator.free(getslot_cmd);

            const gs_result = std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "/bin/sh", "-c", getslot_cmd },
                .max_output_bytes = 1024,
            }) catch break :blk @as(u64, 0);
            defer self.allocator.free(gs_result.stdout);
            defer self.allocator.free(gs_result.stderr);

            // Parse "result":NNNNNN
            if (std.mem.indexOf(u8, gs_result.stdout, "\"result\":")) |idx| {
                const num_start = idx + 9;
                var end = num_start;
                while (end < gs_result.stdout.len and gs_result.stdout[end] >= '0' and gs_result.stdout[end] <= '9') : (end += 1) {}
                if (end > num_start) {
                    const current_slot = std.fmt.parseInt(u64, gs_result.stdout[num_start..end], 10) catch break :blk @as(u64, 0);
                    std.log.debug("[LeaderSchedule] Current slot from RPC: {d} (epoch: {d})\n", .{ current_slot, current_slot / self.generator.slots_per_epoch });
                    break :blk current_slot;
                }
            }
            break :blk @as(u64, 0);
        };
        _ = &effective_slot;

        // Parse leader schedule from response
        self.parseLeaderScheduleResponse(response, effective_slot) catch |err| {
            std.log.debug("[LeaderSchedule] Parse error: {}\n", .{err});
            return err;
        };

        std.log.debug("[LeaderSchedule] Successfully loaded leader schedule\n", .{});
    }

    /// Decode base58 pubkey to 32 bytes
    fn decodeBase58Pubkey(b58: []const u8) ?Pubkey {
        const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // Use a larger buffer to accumulate then extract last 32 bytes
        var result: [64]u8 = [_]u8{0} ** 64;
        var result_len: usize = 0;

        for (b58) |c| {
            // Find digit value
            const digit: u32 = blk: {
                for (alphabet, 0..) |a, i| {
                    if (a == c) break :blk @intCast(i);
                }
                return null; // Invalid character
            };

            // Multiply result by 58 and add digit (big-endian)
            var carry: u32 = digit;
            var i: usize = 0;
            while (i < result_len or carry > 0) : (i += 1) {
                if (i >= 64) return null; // Overflow
                const pos = 63 - i;
                const val: u32 = @as(u32, result[pos]) * 58 + carry;
                result[pos] = @truncate(val & 0xFF);
                carry = val >> 8;
            }
            result_len = @max(result_len, i);
        }

        // Extract last 32 bytes
        var pubkey_data: [32]u8 = undefined;
        @memcpy(&pubkey_data, result[32..64]);
        return Pubkey.fromBytes(pubkey_data);
    }

    /// Parse leader schedule JSON response
    fn parseLeaderScheduleResponse(self: *Self, response: []const u8, base_slot: Slot) !void {
        // Find "result" in response
        const result_start = std.mem.indexOf(u8, response, "\"result\"") orelse return error.InvalidResponse;
        const content = response[result_start..];

        // Parse each validator's slot assignments
        // Format: {"validatorPubkey": [slot1, slot2, ...], ...}
        const epoch = self.generator.getEpoch(base_slot);
        const first_slot = self.generator.getFirstSlotInEpoch(epoch);
        const slots_per_epoch = self.generator.slots_per_epoch;

        // Allocate slot leaders array
        var slot_leaders = try self.allocator.alloc(Pubkey, slots_per_epoch);
        errdefer self.allocator.free(slot_leaders);
        @memset(slot_leaders, Pubkey.fromBytes([_]u8{0} ** 32));

        // Simple parsing: find pubkey:slots pairs
        var pos: usize = 0;
        while (pos < content.len) {
            // Find next pubkey (44 char base58)
            const quote_start = std.mem.indexOfPos(u8, content, pos, "\"") orelse break;
            const quote_end = std.mem.indexOfPos(u8, content, quote_start + 1, "\"") orelse break;
            const key = content[quote_start + 1 .. quote_end];

            // Skip if not a pubkey (44 chars)
            if (key.len < 32 or key.len > 44) {
                pos = quote_end + 1;
                continue;
            }

            // Find slot array
            const array_start = std.mem.indexOfPos(u8, content, quote_end, "[") orelse break;
            const array_end = std.mem.indexOfPos(u8, content, array_start, "]") orelse break;
            const slots_str = content[array_start + 1 .. array_end];

            // Parse pubkey (proper base58 decode)
            const pubkey = decodeBase58Pubkey(key) orelse {
                pos = array_end + 1;
                continue;
            };

            // Parse slots
            var slot_iter = std.mem.splitScalar(u8, slots_str, ',');
            while (slot_iter.next()) |slot_str| {
                const trimmed = std.mem.trim(u8, slot_str, " \t\n");
                if (trimmed.len == 0) continue;

                const slot_num = std.fmt.parseInt(u64, trimmed, 10) catch continue;
                // RPC returns indices (0-based within epoch), not absolute slots
                if (slot_num < slots_per_epoch) {
                    slot_leaders[slot_num] = pubkey;
                }
            }

            pos = array_end + 1;
        }

        // Count non-zero leaders for debug
        var non_zero: usize = 0;
        for (slot_leaders) |leader| {
            if (!std.mem.eql(u8, &leader.data, &[_]u8{0} ** 32)) non_zero += 1;
        }
        std.log.debug("[LeaderSchedule] Parsed {d} non-zero leaders for epoch {d}\n", .{ non_zero, epoch });

        // Add to cache
        const schedule = EpochSchedule{
            .epoch = epoch,
            .first_slot = first_slot,
            .last_slot = first_slot + slots_per_epoch - 1,
            .slot_leaders = slot_leaders,
        };

        try self.addSchedule(schedule);
        std.log.info("[LeaderSchedule] Loaded schedule for epoch {d}", .{epoch});
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "epoch calculation" {
    const allocator = std.testing.allocator;

    const generator = LeaderScheduleGenerator.init(allocator);

    // With warmup: first_normal_epoch=14, first_normal_slot=524256 (correct testnet value)
    try std.testing.expectEqual(@as(Epoch, 0), generator.getEpoch(0));
    try std.testing.expectEqual(@as(Epoch, 0), generator.getEpoch(31)); // epoch 0 = 32 slots
    try std.testing.expectEqual(@as(Epoch, 1), generator.getEpoch(32)); // epoch 1 starts at 32
    try std.testing.expectEqual(@as(Epoch, 14), generator.getEpoch(524288)); // first normal epoch
    try std.testing.expectEqual(@as(Epoch, 15), generator.getEpoch(524288 + 432000));
}
