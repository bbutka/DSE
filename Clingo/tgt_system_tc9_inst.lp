%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_tc9_inst.lp
%% Target: PYNQ-Z2 (same as tgt_system_inst.lp)
%%
%% Risk model notes (multiplicative model):
%%   Non-redundant components (c6, c7, c8):
%%     Risk = Impact * Vulnerability * Logging * ExploitFactor / 100
%%     Capped by max_security_risk.
%%
%%   Redundant group (c1-c5, group size 5):
%%     Uses probabilistic formula:  Risk = Imp * denorm_prob * EF / 1000
%%     Denorm floor = Mu * 10 = 250, so minimum risk = Imp * 250 * EF / 1000
%%     Capped by max_avail_risk.
%%
%%   max_security_risk = 50 keeps the strongest combinations feasible while
%%   still constraining unprotected non-redundant assets.
%%
%%   max_avail_risk = 20 is permissive: allows all security choices,
%%   with the optimizer driving selection via the minimize objective.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

system_capability(max_power,  15000).   % 15W (PYNQ-Z2)
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).

% Dual-risk budget (multiplicative model)
system_capability(max_security_risk, 50).  % multiplicative cap: non-redundant components
system_capability(max_avail_risk,    20).  % probabilistic cap: redundant group

% Alias for opt_resource_enc.lp (uses max_bufg, not max_bufgs)
system_capability(max_bufg, 32).
