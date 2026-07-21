//! Vexor Configuration
//!
//! Handles all validator configuration including:
//! - Command line argument parsing
//! - Configuration file loading (TOML)
//! - Environment variable overrides
//! - Sensible defaults
//!
//! Migrated from Vexor 0.14.1 → vex-fd Zig 0.15.2.
//! Changes: ArrayList → ArrayListUnmanaged with per-call allocator.

const std = @import("std");
const base58 = @import("base58.zig");
const Allocator = std.mem.Allocator;

pub const Config = struct {
    allocator: Allocator,

    // ═══════════════════════════════════════════════════════════════════════
    // IDENTITY
    // ═══════════════════════════════════════════════════════════════════════
    identity_path: ?[]const u8 = null,
    vote_account_path: ?[]const u8 = null,
    /// Layer-A snapshot trust (task #40): trusted validators whose gossip
    /// `SnapshotHashes` must vouch for a snapshot's full (slot,hash) before
    /// Vexor will download it. Populated by repeated `--known-validator <pubkey>`.
    /// EMPTY (default) ⇒ Layer A is OFF ⇒ trust-on-download (current behavior),
    /// exactly mirroring Agave (no `--known-validator` → path skipped). Owned by
    /// this Config's allocator. RULE #1: a 9F-prefix (oracle-node) key is REFUSED here.
    known_validators: []const [32]u8 = &.{},

    // ═══════════════════════════════════════════════════════════════════════
    // PATHS
    // ═══════════════════════════════════════════════════════════════════════
    ledger_path: []const u8 = "/home/sol/ledger",
    ledger_dir: ?[]const u8 = null,
    accounts_path: []const u8 = "/home/sol/accounts-ramdisk",
    accounts_dir: ?[]const u8 = null,
    snapshots_path: []const u8 = "/home/sol/restart_snapshots",
    snapshots_dir: ?[]const u8 = null,
    ramdisk_path: ?[]const u8 = "/mnt/ramdisk",

    // ═══════════════════════════════════════════════════════════════════════
    // NETWORK
    // ═══════════════════════════════════════════════════════════════════════
    rpc_port: u16 = 8899,
    rpc_bind_address: []const u8 = "0.0.0.0",
    rpc_url_override: ?[]const u8 = null,
    /// Canonical Agave RPC tiering (rpc/src/rpc_service.rs:708-713): when false (DEFAULT, matching a
    /// stock voting validator), ONLY the 12 Minimal-trait methods are served; every Full / BankData /
    /// AccountsData / AccountsScan method returns method-not-found (-32601), exactly as Agave does by
    /// not registering those modules. Set true by `--full-rpc-api` (or the `vex-fd rpc` subcommand) to
    /// serve the complete API. Keeping the voting node minimal is what keeps heavy RPC (getProgramAccounts
    /// scans, getBlock/tx-history serving) from competing with consensus for CPU/memory/bandwidth.
    full_rpc_api: bool = false,
    gossip_port: u16 = 8001,
    tpu_port: u16 = 8004,
    tvu_port: u16 = 8003,
    repair_port: u16 = 8002,
    /// IP for the repair interface (from --repair-bind-addr), used in gossip advertisement
    repair_ip: ?[4]u8 = null,
    dynamic_port_range: PortRange = .{ .start = 8100, .end = 8200 },
    entrypoints: []const []const u8 = &.{},
    entrypoints_owned: bool = false,

    /// Public IP address for gossip advertisement.
    /// IMPORTANT: This MUST be set for the network to send shreds to this validator!
    public_ip: ?[4]u8 = null,

    /// Network interface for AF_XDP (empty = auto-detect)
    interface: []const u8 = "",

    /// Bind repair socket to a specific IP (dual-NIC)
    repair_bind_addr: []const u8 = "",
    /// 2026-07-06 gossip source-IP fix: bind the gossip UDP socket to this IP
    /// (dual-NIC hosts). Unset = 0.0.0.0 (kernel picks egress source by route,
    /// which on this host chose the WRONG NIC → pings to the advertised IP were
    /// answered from the other IP → cluster never retained our ContactInfo →
    /// turbine death). Sibling of repair_bind_addr (June NIC repoint fix).
    gossip_bind_addr: []const u8 = "",
    /// 2026-07-06 QUIC/UDP vote-client source-IP fix: bind the vote-sending client
    /// sockets (raw UDP tpu_vote fanout in VoteSender.send AND the native QUIC vote
    /// client) to this IP (dual-NIC hosts). Unset = kernel-routed source (0.0.0.0
    /// bind / no bind at all), which on this host egresses via the DEFAULT route's
    /// IP (.155) while gossip advertises a DIFFERENT IP (.154) — leaders' stake-
    /// weighted QUIC QoS can't match the connection's source to our staked
    /// ContactInfo → unstaked bucket → starved under load → votes never land at
    /// the leader. Sibling of gossip_bind_addr / repair_bind_addr (same dual-NIC
    /// disease, third socket family).
    quic_bind_addr: []const u8 = "",

    /// Network interface for AF_XDP repair socket (empty = same as interface)
    repair_interface: []const u8 = "",

    // ═══════════════════════════════════════════════════════════════════════
    // CLUSTER
    // ═══════════════════════════════════════════════════════════════════════
    cluster: Cluster = .mainnet_beta,
    expected_genesis_hash: ?[]const u8 = null,
    expected_shred_version: ?u16 = null,
    /// Halt-restart safety check per Solana testnet restart docs:
    /// https://docs.google.com/document/d/e/2PACX-1vRRRZipSm5CcZzWD4kTBS8G5VWAY4c9a51TWFShNlVllVs3rRkX-XsIAeXPS7cRVtuJDn2DBJTS3fZ8/pub
    /// Mandated by Agave + Frankendancer for join-late nodes after a halt-restart.
    /// Stored as the original base58 string; bootstrap.zig can decode + cross-check
    /// against snapshot manifest's bank_hash for the corresponding slot.
    /// Was silently dropped pre-2026-05-05; now parsed + logged + available for
    /// programmatic verification.
    expected_bank_hash: ?[]const u8 = null,
    /// Wait-for-supermajority slot per Solana testnet restart docs.
    /// For join-late nodes bootstrapping from a snapshot WELL PAST this slot
    /// (e.g. snapshot at 406260000+ vs supermajority slot 403818246), this is
    /// effectively a no-op visibility flag — the snapshot already incorporates
    /// post-supermajority state. Parsed for transparency + future use.
    wait_for_supermajority: ?u64 = null,

    // ═══════════════════════════════════════════════════════════════════════
    // PERFORMANCE
    // ═══════════════════════════════════════════════════════════════════════
    max_threads: ?usize = null,
    banking_threads: usize = 4,
    replay_threads: usize = 4,

    // ═══════════════════════════════════════════════════════════════════════
    // STORAGE
    // ═══════════════════════════════════════════════════════════════════════
    snapshot_interval_slots: u64 = 500,
    accounts_hash_interval_slots: u64 = 100,
    max_snapshot_age_slots: u64 = 500,
    enable_ramdisk: bool = true,
    ramdisk_size_gb: usize = 32,

    // ═══════════════════════════════════════════════════════════════════════
    // FEATURES (toggles)
    // ═══════════════════════════════════════════════════════════════════════
    enable_gpu: bool = false,
    enable_af_xdp: bool = true,
    enable_io_uring: bool = true,
    /// Enable AsyncIoManager (vex-052) — wires io_uring async account flush.
    /// The store/root.zig init checks @hasField + this bool before spawning
    /// the AsyncIoManager. Default true so the existing infrastructure activates.
    enable_async_io: bool = true,
    /// Enable AF_XDP zero-copy mode (requires NIC driver support: mlx5, ice)
    xdp_zero_copy: bool = false,
    /// Enable FEC Reed-Solomon erasure recovery
    enable_fec_recovery: bool = false,
    /// Enable SIMD-accelerated GF(2^8) for FEC
    enable_simd_fec: bool = true,
    enable_auto_optimize: bool = false,
    enable_metrics: bool = true,
    enable_rpc: bool = true,
    enable_voting: bool = true,
    enable_quic: bool = true,
    enable_h3_datagram: bool = false,
    force_quic: bool = false,
    enable_quic_coalesce: bool = true,
    enable_busy_poll: bool = true,
    quic_target: ?[]const u8 = null,
    quic_insecure: bool = false,
    quic_batch_size_override: u8 = 0,
    shred_version_override: ?u16 = null,

    // ═══════════════════════════════════════════════════════════════════════
    // FAST CATCHUP (experimental)
    // ═══════════════════════════════════════════════════════════════════════
    /// Enable parallel snapshot loading
    enable_parallel_snapshot: bool = true,
    /// Number of threads for parallel snapshot loading (0 = auto-detect CPU count - 1)
    parallel_snapshot_threads: usize = 0,

    /// Force fresh snapshot download even if extracted snapshot exists
    force_fresh_snapshot: bool = false,

    // ═══════════════════════════════════════════════════════════════════════
    // LIMITS
    // ═══════════════════════════════════════════════════════════════════════
    max_ledger_shreds: usize = 50_000_000,
    max_accounts_cache_size: usize = 10_000_000,

    pub const PortRange = struct {
        start: u16,
        end: u16,
    };

    pub const Cluster = enum {
        mainnet_beta,
        testnet,
        devnet,
        localnet,

        // Alias for backward compatibility
        pub const mainnet = Cluster.mainnet_beta;

        pub fn defaultEntrypoints(self: Cluster) []const []const u8 {
            return switch (self) {
                .mainnet_beta => &.{
                    "entrypoint.mainnet-beta.solana.com:8001",
                    "entrypoint2.mainnet-beta.solana.com:8001",
                    "entrypoint3.mainnet-beta.solana.com:8001",
                },
                .testnet => &.{
                    "entrypoint.testnet.solana.com:8001",
                    "entrypoint2.testnet.solana.com:8001",
                },
                .devnet => &.{
                    "entrypoint.devnet.solana.com:8001",
                    "entrypoint2.devnet.solana.com:8001",
                },
                .localnet => &.{},
            };
        }

        pub fn genesisHash(self: Cluster) ?[]const u8 {
            return switch (self) {
                .mainnet_beta => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
                .testnet => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
                .devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
                .localnet => null,
            };
        }
    };

    pub fn getRpcUrl(self: *const Config) []const u8 {
        if (self.rpc_url_override) |url| return url;
        return switch (self.cluster) {
            .mainnet_beta => "https://api.mainnet-beta.solana.com",
            .testnet => "https://api.testnet.solana.com",
            .devnet => "https://api.devnet.solana.com",
            .localnet => "http://localhost:8899",
        };
    }

    /// Load configuration from command line args and/or config file.
    /// Zig 0.15.2: entrypoint list uses ArrayListUnmanaged with per-call allocator.
    pub fn load(allocator: Allocator, args: []const []const u8) !*Config {
        var config = try allocator.create(Config);
        config.* = Config{
            .allocator = allocator,
        };

        // Accumulate entrypoints from CLI — Zig 0.15.2 ArrayListUnmanaged
        var entrypoint_list = std.ArrayListUnmanaged([]const u8){};
        defer entrypoint_list.deinit(allocator);

        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];

            if (std.mem.startsWith(u8, arg, "--enable-feature=")) {
                const feature = arg["--enable-feature=".len..];
                if (std.mem.eql(u8, feature, "af_xdp")) config.enable_af_xdp = true else if (std.mem.eql(u8, feature, "gpu")) config.enable_gpu = true else if (std.mem.eql(u8, feature, "ramdisk")) config.enable_ramdisk = true else if (std.mem.eql(u8, feature, "auto_optimize")) config.enable_auto_optimize = true else if (std.mem.eql(u8, feature, "quic")) config.enable_quic = true else if (std.mem.eql(u8, feature, "io_uring")) config.enable_io_uring = true;
            } else if (std.mem.startsWith(u8, arg, "--disable-feature=")) {
                const feature = arg["--disable-feature=".len..];
                if (std.mem.eql(u8, feature, "af_xdp")) config.enable_af_xdp = false else if (std.mem.eql(u8, feature, "gpu")) config.enable_gpu = false else if (std.mem.eql(u8, feature, "ramdisk")) config.enable_ramdisk = false else if (std.mem.eql(u8, feature, "auto_optimize")) config.enable_auto_optimize = false else if (std.mem.eql(u8, feature, "quic")) config.enable_quic = false else if (std.mem.eql(u8, feature, "io_uring")) config.enable_io_uring = false;
            } else if (std.mem.eql(u8, arg, "--identity")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.identity_path = args[i];
            } else if (std.mem.eql(u8, arg, "--vote-account")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.vote_account_path = args[i];
            } else if (std.mem.eql(u8, arg, "--ledger")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.ledger_path = args[i];
            } else if (std.mem.eql(u8, arg, "--accounts")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.accounts_path = args[i];
            } else if (std.mem.eql(u8, arg, "--rpc-port")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.rpc_port = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--rpc-url")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.rpc_url_override = args[i];
            } else if (std.mem.eql(u8, arg, "--gossip-port")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.gossip_port = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--cluster")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.cluster = std.meta.stringToEnum(Cluster, args[i]) orelse return error.InvalidCluster;
            } else if (std.mem.eql(u8, arg, "--testnet")) {
                config.cluster = .testnet;
                if (config.vote_account_path == null) {
                    config.vote_account_path = "/home/sol/.secrets/vexor/vote-account-keypair.json";
                }
            } else if (std.mem.eql(u8, arg, "--mainnet-beta") or std.mem.eql(u8, arg, "--mainnet")) {
                config.cluster = .mainnet_beta;
            } else if (std.mem.eql(u8, arg, "--devnet")) {
                config.cluster = .devnet;
            } else if (std.mem.eql(u8, arg, "--localnet")) {
                config.cluster = .localnet;
            } else if (std.mem.eql(u8, arg, "--enable-gpu") or std.mem.eql(u8, arg, "--cuda")) {
                config.enable_gpu = true;
            } else if (std.mem.eql(u8, arg, "--enable-af-xdp")) {
                config.enable_af_xdp = true;
            } else if (std.mem.eql(u8, arg, "--disable-af-xdp") or std.mem.eql(u8, arg, "--no-af-xdp")) {
                config.enable_af_xdp = false;
            } else if (std.mem.eql(u8, arg, "--xdp-zero-copy")) {
                config.xdp_zero_copy = true;
                std.log.debug("[CONFIG] AF_XDP zero-copy mode ENABLED (requires bnxt_en/mlx5/ice NIC driver)\n", .{});
            } else if (std.mem.eql(u8, arg, "--enable-fec-recovery")) {
                config.enable_fec_recovery = true;
                std.log.debug("[CONFIG] FEC Reed-Solomon recovery ENABLED\n", .{});
            } else if (std.mem.eql(u8, arg, "--enable-simd-fec")) {
                config.enable_simd_fec = true;
                std.log.debug("[CONFIG] SIMD-accelerated FEC ENABLED (GFNI/AVX2)\n", .{});
            } else if (std.mem.eql(u8, arg, "--enable-io-uring")) {
                config.enable_io_uring = true;
            } else if (std.mem.eql(u8, arg, "--disable-io-uring") or std.mem.eql(u8, arg, "--no-io-uring")) {
                config.enable_io_uring = false;
            } else if (std.mem.eql(u8, arg, "--enable-quic")) {
                config.enable_quic = true;
            } else if (std.mem.eql(u8, arg, "--disable-quic") or std.mem.eql(u8, arg, "--no-quic")) {
                config.enable_quic = false;
            } else if (std.mem.eql(u8, arg, "--force-quic")) {
                config.enable_quic = true;
                config.force_quic = true;
            } else if (std.mem.eql(u8, arg, "--no-force-quic")) {
                config.force_quic = false;
            } else if (std.mem.eql(u8, arg, "--no-busy-poll")) {
                config.enable_busy_poll = false;
            } else if (std.mem.eql(u8, arg, "--enable-h3-datagram")) {
                config.enable_h3_datagram = true;
            } else if (std.mem.eql(u8, arg, "--disable-h3-datagram")) {
                config.enable_h3_datagram = false;
            } else if (std.mem.eql(u8, arg, "--enable-quic-coalesce")) {
                config.enable_quic_coalesce = true;
            } else if (std.mem.eql(u8, arg, "--disable-quic-coalesce")) {
                config.enable_quic_coalesce = false;
            } else if (std.mem.eql(u8, arg, "--quic-target")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.quic_target = args[i];
            } else if (std.mem.eql(u8, arg, "--quic-insecure")) {
                config.quic_insecure = true;
            } else if (std.mem.eql(u8, arg, "--quic-batch-size")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.quic_batch_size_override = try std.fmt.parseInt(u8, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--shred-version")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.shred_version_override = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--enable-parallel-snapshot")) {
                config.enable_parallel_snapshot = true;
            } else if (std.mem.eql(u8, arg, "--disable-parallel-snapshot")) {
                config.enable_parallel_snapshot = false;
            } else if (std.mem.eql(u8, arg, "--parallel-snapshot-threads")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.parallel_snapshot_threads = try std.fmt.parseInt(usize, args[i], 10);
                config.enable_parallel_snapshot = true;
            } else if (std.mem.eql(u8, arg, "--force-fresh-snapshot")) {
                config.force_fresh_snapshot = true;
            } else if (std.mem.eql(u8, arg, "--interface")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.interface = args[i];
            } else if (std.mem.eql(u8, arg, "--gossip-bind-addr")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.gossip_bind_addr = args[i];
                std.log.debug("[CONFIG] Gossip socket will bind to {s} (dual-NIC)\n", .{args[i]});
            } else if (std.mem.eql(u8, arg, "--quic-bind-addr")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.quic_bind_addr = args[i];
                std.log.debug("[CONFIG] QUIC/UDP vote-client sockets will bind to {s} (dual-NIC)\n", .{args[i]});
            } else if (std.mem.eql(u8, arg, "--repair-bind-addr")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.repair_bind_addr = args[i];
                config.repair_ip = parseIpv4(args[i]);
                std.log.debug("[CONFIG] Repair socket will bind to {s} (dual-NIC)\n", .{args[i]});
            } else if (std.mem.eql(u8, arg, "--repair-interface")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.repair_interface = args[i];
                std.log.debug("[CONFIG] Repair AF_XDP interface: {s}\n", .{args[i]});
            } else if (std.mem.eql(u8, arg, "--enable-ramdisk")) {
                config.enable_ramdisk = true;
            } else if (std.mem.eql(u8, arg, "--disable-ramdisk")) {
                config.enable_ramdisk = false;
            } else if (std.mem.eql(u8, arg, "--snapshots")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.snapshots_path = args[i];
            } else if (std.mem.eql(u8, arg, "--log")) {
                i += 1;
                // Log path - handled by runtime
            } else if (std.mem.eql(u8, arg, "--known-validator")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                // RULE #1 (key isolation): NEVER let a oracle-node 9F-prefix (base58)
                // key into Vexor's known-validator set — that would cross
                // consensus-affecting trust between the two independently-operated
                // validators on this host. Refuse loudly rather than ingest it.
                if (std.mem.startsWith(u8, args[i], "9f") or std.mem.startsWith(u8, args[i], "9F")) {
                    std.log.err("[CONFIG] --known-validator {s} has the 9F oracle-node prefix — REFUSED (key-isolation policy)", .{args[i]});
                    return error.KnownValidatorIsDeniedHost;
                }
                var pk: [32]u8 = undefined;
                base58.decodeToBuf(args[i], &pk) catch {
                    std.log.err("[CONFIG] --known-validator {s} is not a valid 32-byte base58 pubkey", .{args[i]});
                    return error.InvalidKnownValidator;
                };
                // Repeatable flag: append to the owned slice (grow by one).
                const old_kv = config.known_validators;
                const grown = try allocator.alloc([32]u8, old_kv.len + 1);
                @memcpy(grown[0..old_kv.len], old_kv);
                grown[old_kv.len] = pk;
                if (old_kv.len > 0) allocator.free(@constCast(old_kv));
                config.known_validators = grown;
                std.log.info("[CONFIG] --known-validator registered ({d} total) — Layer-A snapshot trust ENABLED", .{config.known_validators.len});
            } else if (std.mem.eql(u8, arg, "--expected-genesis-hash")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.expected_genesis_hash = args[i];
            } else if (std.mem.eql(u8, arg, "--expected-shred-version")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                const parsed_version = try std.fmt.parseInt(u16, args[i], 10);
                config.expected_shred_version = parsed_version;
            } else if (std.mem.eql(u8, arg, "--expected-bank-hash")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.expected_bank_hash = args[i];
            } else if (std.mem.eql(u8, arg, "--wait-for-supermajority")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.wait_for_supermajority = try std.fmt.parseInt(u64, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--only-known-rpc")) {
                // Only connect to known validators
            } else if (std.mem.eql(u8, arg, "--limit-ledger-size")) {
                if (i + 1 < args.len and args[i + 1][0] != '-') {
                    i += 1;
                    config.max_ledger_shreds = try std.fmt.parseInt(usize, args[i], 10);
                }
            } else if (std.mem.eql(u8, arg, "--no-voting")) {
                config.vote_account_path = null;
            } else if (std.mem.eql(u8, arg, "--full-rpc-api")) {
                config.full_rpc_api = true;
            } else if (std.mem.eql(u8, arg, "--ramdisk-size")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.ramdisk_size_gb = try std.fmt.parseInt(usize, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--disable-auto-optimize") or std.mem.eql(u8, arg, "--no-auto-optimize")) {
                config.enable_auto_optimize = false;
            } else if (std.mem.eql(u8, arg, "--entrypoint")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                // Zig 0.15.2: pass allocator per call to ArrayListUnmanaged
                try entrypoint_list.append(allocator, args[i]);
            } else if (std.mem.eql(u8, arg, "--public-ip") or std.mem.eql(u8, arg, "--gossip-host")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.public_ip = parseIpv4(args[i]) orelse return error.InvalidIpAddress;
            } else if (std.mem.eql(u8, arg, "--tvu-port")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.tvu_port = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--repair-port")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                config.repair_port = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, arg, "--dynamic-port-range")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                var parts = std.mem.splitScalar(u8, args[i], '-');
                const start_str = parts.next() orelse return error.InvalidPortRange;
                const end_str = parts.next() orelse return error.InvalidPortRange;
                config.dynamic_port_range = .{
                    .start = try std.fmt.parseInt(u16, start_str, 10),
                    .end = try std.fmt.parseInt(u16, end_str, 10),
                };
            } else if (std.mem.eql(u8, arg, "--config")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                try config.loadFromFile(args[i]);
            }
        }

        // Use CLI entrypoints if provided, otherwise use cluster defaults.
        // Zig 0.15.2: toOwnedSlice takes allocator
        if (entrypoint_list.items.len > 0) {
            config.entrypoints = try entrypoint_list.toOwnedSlice(allocator);
            config.entrypoints_owned = true;
            std.log.debug("[Config] Using {d} CLI-provided entrypoints\n", .{config.entrypoints.len});
        } else {
            config.entrypoints = config.cluster.defaultEntrypoints();
            config.entrypoints_owned = false;
            std.log.debug("[Config] Using default entrypoints for {s}\n", .{@tagName(config.cluster)});
        }

        return config;
    }

    /// Load configuration from a TOML file
    pub fn loadFromFile(self: *Config, path: []const u8) !void {
        _ = self;
        _ = path;
        // TODO: Implement TOML parsing
    }

    pub fn deinit(self: *Config) void {
        if (self.entrypoints_owned) {
            self.allocator.free(self.entrypoints);
        }
        self.allocator.destroy(self);
    }

    /// Validate the configuration
    pub fn validate(self: *const Config) !void {
        if (self.identity_path == null) {
            return error.IdentityRequired;
        }

        if (self.vote_account_path == null) {
            std.log.debug("Warning: No vote account specified. Running as non-voting node.\n", .{});
        }

        if (self.dynamic_port_range.start >= self.dynamic_port_range.end) {
            return error.InvalidPortRange;
        }

        if (self.public_ip == null) {
            std.log.debug("\nWARNING: No --public-ip specified!\n", .{});
            std.log.debug("   The network won't know where to send shreds.\n", .{});
            std.log.debug("   Use: --public-ip <YOUR_PUBLIC_IP>\n\n", .{});
        } else if (self.cluster != .localnet and isLoopbackIpv4(self.public_ip.?)) {
            std.log.debug("\nWARNING: --public-ip is loopback for non-localnet!\n", .{});
            std.log.debug("   Use a publicly reachable IP for testnet/mainnet.\n\n", .{});
        }

        if (self.entrypoints.len == 0 and self.cluster != .localnet) {
            std.log.debug("\nWARNING: No gossip entrypoints configured!\n", .{});
            std.log.debug("   Gossip won't find peers. Provide --entrypoint or set --cluster.\n\n", .{});
        }
    }

    /// Get the public IP as bytes for socket addresses
    pub fn getPublicIpBytes(self: *const Config) [4]u8 {
        return self.public_ip orelse .{ 0, 0, 0, 0 };
    }
};

/// Parse an IPv4 address string like "192.168.1.1" into bytes
fn parseIpv4(ip_str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, ip_str, '.');

    var i: usize = 0;
    while (parts.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }

    if (i != 4) return null;
    return result;
}

fn isLoopbackIpv4(ip: [4]u8) bool {
    return ip[0] == 127;
}

/// Value-parsed boolean env gate (2026-07-10): armed iff the var is SET and its value is not an
/// explicit off ("0" / "false"). This is the parse main.zig's bakeProdEnvDefaults override contract
/// ("an explicit VEX_X=0 ... still overrides") requires of every baked flag's consumer —
/// existence-only checks (`getenv(..) != null`) make `VEX_X=0` indistinguishable from `VEX_X=1`
/// (the VEX_PARALLEL_EXEC=0 offline-gate defect: every prior "serial" repro987 gate silently ran
/// the wave path because the gate exports =0 while the consumer only tested existence). Pure over
/// the looked-up value ⟹ KAT-able without touching the process environment.
pub fn envFlagValueArmed(v: ?[]const u8) bool {
    const val = v orelse return false;
    if (std.mem.eql(u8, val, "0")) return false;
    if (std.mem.eql(u8, val, "false")) return false;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "envFlagValueArmed: baked VEX_WATCHDOG_RESTART=0 disarms exit-for-supervisor (alarm-only watchdog)" {
    // Operator policy 2026-07-15: no automated node down/up cycles; wedges self-heal
    // in-process (chain-defer tip-guard) or alarm for MANUAL restart. The baked
    // default is now "0", which MUST read as NOT armed (the watchdog then logs
    // [HEALTH-ALERT] but never exit(1)s). An explicit operator "1" still arms it.
    try std.testing.expect(!envFlagValueArmed("0"));
    try std.testing.expect(!envFlagValueArmed("false"));
    try std.testing.expect(envFlagValueArmed("1"));
    try std.testing.expect(!envFlagValueArmed(null));
}

test "config defaults" {
    const allocator = std.testing.allocator;
    const config = try Config.load(allocator, &.{});
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8899), config.rpc_port);
    try std.testing.expectEqual(@as(u16, 8001), config.gossip_port);
    try std.testing.expectEqual(Config.Cluster.mainnet_beta, config.cluster);
}

test "config with args" {
    const allocator = std.testing.allocator;
    const args = &.{ "--rpc-port", "9000", "--cluster", "testnet" };
    const config = try Config.load(allocator, args);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 9000), config.rpc_port);
    try std.testing.expectEqual(Config.Cluster.testnet, config.cluster);
}

test "envFlagValueArmed: explicit 0/false disarm, set-nonzero arms, unset disarms" {
    // The VEX_PARALLEL_EXEC=0 offline-gate defect: the consumer was existence-only, so the
    // repro987 gate's explicit =0 ARMED the wave path. This KATs the value-parse contract.
    try std.testing.expect(!envFlagValueArmed(null)); // unset → off
    try std.testing.expect(!envFlagValueArmed("0")); // explicit off (gate/operator override)
    try std.testing.expect(!envFlagValueArmed("false")); // explicit off (alt spelling)
    try std.testing.expect(envFlagValueArmed("1")); // proven-deploy arm value
    try std.testing.expect(envFlagValueArmed("")); // set-but-empty = legacy existence arm
    try std.testing.expect(envFlagValueArmed("yes")); // any other value arms (existence semantics)
}

test "cluster entrypoints" {
    const mainnet_entrypoints = Config.Cluster.mainnet.defaultEntrypoints();
    try std.testing.expect(mainnet_entrypoints.len > 0);

    const genesis = Config.Cluster.mainnet.genesisHash();
    try std.testing.expect(genesis != null);
}
