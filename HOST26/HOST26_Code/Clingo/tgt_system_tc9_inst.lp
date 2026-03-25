%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_tc9_inst.lp
%% Target: PYNQ-Z2 (same as tgt_system_inst.lp)
%% Adjusted for testCase9: max_asset_risk relaxed to 500
%% because standalone components (c6, c8) have tight latency
%% budgets that prevent zero_trust + zero_trust_logger, so
%% the minimum achievable risk exceeds 25 for high-impact assets.
%% The optimiser still minimises risk subject to this feasible cap.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

system_capability(max_power,  15000).   % 15W (PYNQ-Z2)
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).

% Per-asset risk cap: relaxed to 500 for testCase9
% (tight latency budgets on c6r1/c8r1 make cap=25 infeasible)
system_capability(max_asset_risk, 500).

% Alias for opt_resource_enc.lp (uses max_bufg, not max_bufgs)
system_capability(max_bufg, 32).
