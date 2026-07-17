//! Vexor Consensus Module
//!
//! Implements Solana consensus mechanisms (Tower BFT, current production
//! consensus): vote lockout, fork choice, propagation gating, leader
//! schedule. (The experimental Alpenglow scaffold that used to live here
//! was DEAD — gated on a build_options field this module never received —
//! and did not migrate into this tree; see REBUILD-LEDGER.md module 3.)

const std = @import("std");

pub const tower = @import("tower.zig");
pub const fork_choice = @import("fork_choice.zig");
pub const propagation = @import("propagation.zig");
pub const vote = @import("vote.zig");
pub const vote_tx = @import("vote_tx.zig");
pub const leader_schedule = @import("leader_schedule.zig");

// Re-export main types
pub const TowerBft = tower.TowerBft;
pub const ForkChoice = fork_choice.ForkChoice;
pub const Vote = vote.Vote;
pub const LeaderScheduleGenerator = leader_schedule.LeaderScheduleGenerator;
pub const LeaderScheduleCache = leader_schedule.LeaderScheduleCache;

test {
    std.testing.refAllDecls(@This());
}
