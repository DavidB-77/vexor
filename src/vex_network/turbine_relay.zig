//! Turbine Message Relay
//!
//! Handles high-performance retransmission of shreds to downstream peers.
//! Uses a thread pool to offload I/O operations from the main verification loop.
//!
//! Architecture:
//! - Receives verified shreds + list of destinations (from TurbineTree)
//! - Batches packets for AF_XDP or uses dedicated threads for UDP sendto()
//! - Handles Alpenglow V3 variant specific logic (if needed for forwarding)

const std = @import("std");
const core = @import("core");
const packet = @import("packet.zig");
const socket = @import("socket.zig");
const turbine_tree = @import("turbine_tree.zig");
const runtime = @import("vex_svm");
const accelerated_io = @import("accelerated_io.zig");

pub const TurbineRelay = struct {
    allocator: std.mem.Allocator,

    /// Thread pool for parallel retransmission
    thread_pool: *std.Thread.Pool,

    /// Reference to IO backend (AF_XDP or Socket)
    /// We use the TVU's IO for sending if possible, or a separate socket
    io_interface: IoInterface,

    const Self = @This();

    pub const IoInterface = union(enum) {
        accelerated: *accelerated_io.AcceleratedIO,
        socket: *socket.UdpSocket,
        none,
    };

    pub fn init(allocator: std.mem.Allocator, thread_pool: *std.Thread.Pool) Self {
        return .{
            .allocator = allocator,
            .thread_pool = thread_pool,
            .io_interface = .none,
        };
    }

    pub fn setIoInterface(self: *Self, io: IoInterface) void {
        self.io_interface = io;
    }

    /// Relay a verified shred to downstream peers
    /// Uses the TurbineTree to determine destinations
    pub fn relayShred(self: *Self, shred: *const runtime.Shred, packet_data: []const u8, tree: *turbine_tree.TurbineTree, leader: core.Pubkey, fanout: usize) !void {
        // 1. Determine children
        // We need a stable buffer for children to avoid allocation in hot path if possible
        // For now using an ArrayList created here
        var children = std.ArrayList(turbine_tree.TurbineNode).init(self.allocator);
        defer children.deinit();

        const shred_id = turbine_tree.ShredId{
            .slot = shred.slot(),
            .index = shred.index(),
            .shred_type = if (shred.isData()) .data else .code,
        };

        // Get downstream peers for this specific shred
        _ = try tree.getRetransmitChildren(&children, leader, shred_id, fanout);

        if (children.items.len == 0) {
            std.log.debug("[RELAY] No children found for shred {d}! (Leader={any}, ID={any})\n", .{ shred.index(), leader, shred_id });
            return;
        }

        // 2. Schedule retransmission
        // We clone the packet data because the original buffer might be reused by the time the thread runs
        const packet_copy = try self.allocator.dupe(u8, packet_data);

        // Clone destinations (TurbineNode contains copies of data so this is fine, but ArrayList struct is on stack)
        const destinations = try self.allocator.dupe(turbine_tree.TurbineNode, children.items);

        // Spawn task in thread pool
        try self.thread_pool.spawn(runRelayTask, .{ self, packet_copy, destinations });
    }

    /// Per-worker one-shot "already pinned" guard. `std.Thread.Pool` exposes no per-worker init
    /// hook, so each pool worker pins ITSELF on the first relay task it runs (thread-local → done
    /// once per worker, not per task). Without this the 4 pool workers (tvu.zig n_jobs=4) inherit
    /// the validator's wide taskset (1-3,5-27) and a retransmit BURST can momentarily schedule a
    /// relay worker onto a hot consensus core (replay 16 / verify 8-15 / gossip 24) — the exact
    /// collision the tile→core topology is meant to prevent. (Runtime audit 2026-06-22: these were
    /// the only burst-capable unpinned floaters; all CPU-burning consensus threads were already
    /// pinned.) Confine them to a MASK over cold CCX0 {1,2,3} (its own idle L3, fully off the hot
    /// pipeline, inside the widened taskset) — a multi-core mask lets the OS load-balance the 4
    /// workers across {1,2,3} rather than stacking on one core.
    threadlocal var relay_pinned: bool = false;

    /// Worker task for retransmission
    fn runRelayTask(self: *Self, packet_data: []const u8, destinations: []const turbine_tree.TurbineNode) void {
        if (!relay_pinned) {
            // Self-contained bit math (no vex_topo import — keeps turbine_relay's module/test graph
            // dependency-free; identical cpu_set construction to vex_topo.pinCore). Mask = cold CCX0
            // relief cores {1,2,3} == vex_topo.COLD_CCX0_RELIEF.
            var cpu_set = [_]usize{0} ** 16;
            // Mask = free CCX5 cores {21,22,23} (produce=20 is the only CCX5 tile, leader-gated/idle).
            // Moved OFF CCX0 {1,2,3} (2026-06-22): CCX0 core0=OS/main, cores 1-3 are the cold reserve
            // earmarked for the future parallel-exec worker pool ({2,3}) — keep relay off it. These are
            // free hot-taskset cores off the consensus pipeline (recv4/verify8-15/replay16).
            inline for (.{ 21, 22, 23 }) |c| {
                cpu_set[c / @bitSizeOf(usize)] |= @as(usize, 1) << @intCast(c % @bitSizeOf(usize));
            }
            _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
            relay_pinned = true;
        }
        std.log.debug("[RELAY] Processing task for {d} destinations\n", .{destinations.len});
        defer self.allocator.free(packet_data);
        defer self.allocator.free(destinations);

        // In a real optimized implementation, we would use sendmmsg or XDP batching here.
        // For now, loop and send.

        switch (self.io_interface) {
            .accelerated => |io| {
                for (destinations) |dest| {
                    if (dest.tvu_addr) |addr| {
                        io.send(packet_data, addr) catch |err| {
                            std.log.debug("[RELAY] AF_XDP send failed: {}", .{err});
                        };
                    }
                }
            },
            .socket => |sock| {
                for (destinations) |dest| {
                    if (dest.tvu_addr) |addr| {
                        std.log.debug("[RELAY] Sending to {any}\n", .{addr});
                        _ = sock.sendTo(packet_data, addr.toStd()) catch |err| {
                            // Ignore send errors in hot path to keep flowing
                            std.log.debug("[RELAY] Socket send failed: {}\n", .{err});
                        };
                    }
                }
            },
            .none => {
                std.log.warn("[RELAY] No IO interface configured, dropping shred", .{});
            },
        }
    }
};
