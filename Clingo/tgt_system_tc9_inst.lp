%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_tc9_inst.lp
%% Target: PYNQ-Z2 (same as tgt_system_inst.lp)
%%
%% Risk model notes (additive model, updated):
%%   Non-redundant components (c6, c7, c8):
%%     Risk = Impact + DomainBonus - SecurityProtect - LogProtect (clamped 0)
%%     Maximum additive risk = 5 (impact) + 3 (high domain) = 8 (no security)
%%
%%   Redundant group (c1-c5, group size 5):
%%     Uses probabilistic formula:  Risk = Imp * denorm_prob / 100
%%     Denorm floor = Mu * 10 = 250, so minimum risk = Imp * 250/100
%%     For impact=5: minimum achievable risk = 12 (any security choice)
%%     For impact=1: minimum achievable risk = 2
%%
%%   The two formulas are on different scales.  max_asset_risk is set high
%%   enough to be feasible for the redundant group while still being a
%%   meaningful safeguard against completely unprotected non-redundant assets.
%%   The optimizer (minimize objective) drives security selection in practice.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

system_capability(max_power,  15000).   % 15W (PYNQ-Z2)
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).

% Per-asset risk cap: 20 is the minimum feasible for TC9's 5-component
% redundant group (min risk ≈ 12 for impact=5 with best security).
% For non-redundant components the additive model max is 8, so this cap
% never binds them — the minimiser objective handles their optimisation.
system_capability(max_asset_risk, 20).

% Alias for opt_resource_enc.lp (uses max_bufg, not max_bufgs)
system_capability(max_bufg, 32).
