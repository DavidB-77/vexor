//! Vexor Snapshot Service
//!
//! Periodic snapshot generation at configurable slot intervals.
//! Captures bank state and accounts at freeze time, writes to disk
//! in Solana-compatible format for serving to other validators.
//!
//! Pipeline:
//! 1. Replay stage notifies after freeze at snapshot-eligible slot
//! 2. Service captures: slot, bank_hash, epoch, accounts hash
//! 3. Writes accounts to AppendVec file(s) in snapshot directory
//! 4. Writes status marker for serving
//! 5. Cleans up old snapshots (keep last 2)

const std = @import("std");
const types = @import("types.zig");
const Hash = types.Hash;

/// Snapshot service configuration
pub const SnapshotConfig = struct {
    /// Generate a full snapshot every N slots (default: 25000, ~3.5 hours)
    full_snapshot_interval: u64 = 25000,
    /// Generate an incremental snapshot every N slots (default: 500, ~4 minutes)
    incremental_interval: u64 = 500,
    /// Maximum number of full snapshots to keep
    max_full_snapshots: u32 = 2,
    /// Maximum number of incremental snapshots to keep
    max_incremental_snapshots: u32 = 4,
    /// Base directory for snapshots
    snapshot_dir: []const u8 = "/mnt/snapshots/vexor-testnet",
};

/// Snapshot metadata captured at freeze time
pub const SnapshotMeta = struct {
    slot: u64,
    bank_hash: [32]u8,
    parent_slot: u64,
    epoch: u64,
    lamports_total: u64,
    accounts_count: u64,
    timestamp: i64,
};

/// Snapshot service state
pub const SnapshotService = struct {
    allocator: std.mem.Allocator,
    config: SnapshotConfig,
    last_full_snapshot_slot: u64,
    last_incremental_slot: u64,
    snapshots_generated: u64,

    pub fn init(allocator: std.mem.Allocator, config: SnapshotConfig) SnapshotService {
        return .{
            .allocator = allocator,
            .config = config,
            .last_full_snapshot_slot = 0,
            .last_incremental_slot = 0,
            .snapshots_generated = 0,
        };
    }

    /// Check if this slot should trigger a snapshot.
    pub fn shouldSnapshot(self: *const SnapshotService, slot: u64) bool {
        if (slot == 0) return false;
        // Full snapshot at larger intervals
        if (slot % self.config.full_snapshot_interval == 0) return true;
        // Incremental snapshot at smaller intervals
        if (slot % self.config.incremental_interval == 0) return true;
        return false;
    }

    /// Check if this is a full snapshot slot (vs incremental)
    pub fn isFullSnapshotSlot(self: *const SnapshotService, slot: u64) bool {
        return slot % self.config.full_snapshot_interval == 0;
    }

    /// Returns true if periodic FULL snapshot CREATION is enabled. Gated behind
    /// the `VEX_SNAPSHOT_CREATE` env (default OFF) so the live replay path is
    /// unchanged by default — building a full snapshot on the replay thread is a
    /// multi-second stall over 86.7M accounts and would risk liveness. When OFF,
    /// onSlotFrozen only writes the lightweight metadata marker (as before). The
    /// full create path (manifest + tar.zst) is exercised on demand via the RPC
    /// `saveAccountsSnapshot` instead. v2: a dedicated background snapshot thread
    /// reading a frozen-bank handoff can flip this on safely.
    pub fn periodicCreateEnabled() bool {
        return std.process.hasEnvVarConstant("VEX_SNAPSHOT_CREATE");
    }

    /// Notify the service that a slot has been frozen.
    /// If it's a snapshot-eligible slot, begins snapshot generation.
    ///
    /// LIVENESS CAVEAT: by default this only writes a metadata marker (no full
    /// snapshot build) so it cannot stall replay. Full periodic creation is
    /// gated behind `VEX_SNAPSHOT_CREATE` (periodicCreateEnabled) and is NOT
    /// wired into this marker-only path in v1 — use the RPC for on-demand full
    /// snapshots.
    pub fn onSlotFrozen(self: *SnapshotService, meta: SnapshotMeta) void {
        if (!self.shouldSnapshot(meta.slot)) return;

        const is_full = self.isFullSnapshotSlot(meta.slot);
        const snap_type: []const u8 = if (is_full) "FULL" else "INCREMENTAL";

        std.log.debug("[SNAPSHOT] {s} snapshot at slot {d}: hash={x:0>8}.. accounts={d} lamports={d:.2} SOL\n", .{
            snap_type,
            meta.slot,
            std.mem.readInt(u32, meta.bank_hash[0..4], .big),
            meta.accounts_count,
            @as(f64, @floatFromInt(meta.lamports_total)) / 1e9,
        });

        if (is_full) {
            self.last_full_snapshot_slot = meta.slot;
        }
        self.last_incremental_slot = meta.slot;
        self.snapshots_generated += 1;

        // Write snapshot marker file (metadata for serving)
        self.writeSnapshotMarker(meta) catch |err| {
            std.log.debug("[SNAPSHOT] Failed to write marker: {any}\n", .{err});
        };
    }

    /// Write a small marker file with snapshot metadata.
    /// The actual AppendVec accounts data is already on disk in the accounts directory.
    fn writeSnapshotMarker(self: *SnapshotService, meta: SnapshotMeta) !void {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/snapshot-{d}-{x:0>16}.marker", .{
            self.config.snapshot_dir,
            meta.slot,
            std.mem.readInt(u64, meta.bank_hash[0..8], .little),
        }) catch return;

        const file = std.fs.cwd().createFile(path, .{}) catch return;
        defer file.close();

        // Write metadata as fixed-size binary
        var buf: [128]u8 = undefined;
        var off: usize = 0;
        @memcpy(buf[off..][0..8], "VXSNAP01");
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], meta.slot, .little);
        off += 8;
        @memcpy(buf[off..][0..32], &meta.bank_hash);
        off += 32;
        std.mem.writeInt(u64, buf[off..][0..8], meta.parent_slot, .little);
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], meta.epoch, .little);
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], meta.lamports_total, .little);
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], meta.accounts_count, .little);
        off += 8;
        std.mem.writeInt(i64, buf[off..][0..8], meta.timestamp, .little);
        off += 8;

        file.writeAll(buf[0..off]) catch {};

        // Clean up old markers
        self.cleanupOldSnapshots() catch {};
    }

    /// Remove old snapshot markers beyond the configured retention limits.
    fn cleanupOldSnapshots(self: *SnapshotService) !void {
        var dir = std.fs.cwd().openDir(self.config.snapshot_dir, .{ .iterate = true }) catch return;
        defer dir.close();

        var markers: [32]u64 = undefined;
        var count: usize = 0;

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".marker")) continue;
            if (count < 32) {
                // Parse slot from filename: snapshot-{slot}-{hash}.marker
                const name = entry.name;
                if (std.mem.indexOf(u8, name, "-")) |dash1| {
                    const rest = name[dash1 + 1 ..];
                    if (std.mem.indexOf(u8, rest, "-")) |dash2| {
                        markers[count] = std.fmt.parseInt(u64, rest[0..dash2], 10) catch continue;
                        count += 1;
                    }
                }
            }
        }

        if (count <= self.config.max_full_snapshots + self.config.max_incremental_snapshots) return;

        // Sort and remove oldest
        std.mem.sort(u64, markers[0..count], {}, std.sort.asc(u64));
        const to_remove = count - (self.config.max_full_snapshots + self.config.max_incremental_snapshots);
        for (0..to_remove) |i| {
            var del_buf: [256]u8 = undefined;
            // Re-scan to find the file matching this slot
            var del_it = dir.iterate();
            while (del_it.next() catch null) |del_entry| {
                if (!std.mem.endsWith(u8, del_entry.name, ".marker")) continue;
                const del_name = del_entry.name;
                if (std.mem.indexOf(u8, del_name, "-")) |d1| {
                    const del_rest = del_name[d1 + 1 ..];
                    if (std.mem.indexOf(u8, del_rest, "-")) |d2| {
                        const slot = std.fmt.parseInt(u64, del_rest[0..d2], 10) catch continue;
                        if (slot == markers[i]) {
                            _ = std.fmt.bufPrint(&del_buf, "{s}", .{del_entry.name}) catch continue;
                            dir.deleteFile(del_entry.name) catch {};
                            break;
                        }
                    }
                }
            }
        }
    }
};
