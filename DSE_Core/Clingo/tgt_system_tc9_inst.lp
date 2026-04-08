%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_tc9_inst.lp
%% Target: PYNQ-Z2 (Zynq-7000, xc7z020clg400-1)
%%
%% DUAL-RISK BUDGET (Option A)
%% ============================
%% Non-redundant components (c6, c7, c8) - multiplicative model:
%%   Risk = Impact * Exposure * Realtime * ExploitFactor / 100
%%   max_security_risk = 50 keeps the strongest combinations feasible while
%%   still ruling out weak pairings on high-impact assets.
%%
%% Redundant group (c1-c5, group size 5) - probabilistic model:
%%   Risk = Imp * denorm_prob * ExploitFactor / 1000
%%   Denorm floor = Mu*10 = 250, so minimum risk = Imp * 250 * ExploitFactor / 1000
%%   For impact=5 and neutral exploitability: minimum = 12
%%   max_avail_risk = 20 is permissive: allows all security choices,
%%   letting the minimiser drive selection.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

system_capability(max_power,  15000).   % 15W (PYNQ-Z2)
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).
system_capability(max_attack_depth, 5).

% Dual-risk budget caps (see header comment for derivation).
system_capability(max_security_risk, 50).  % multiplicative cap: non-redundant components
system_capability(max_avail_risk,   20).   % probabilistic cap: redundant group
