%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_tc9_inst.lp
%% Target: PYNQ-Z2 (Zynq-7000, xc7z020clg400-1)
%%
%% DUAL-RISK BUDGET (Option A)
%% ============================
%% Non-redundant components (c6, c7, c8) — additive model:
%%   Risk = Impact + DomainBonus - SecurityProtect - LogProtect (clamped >= 0)
%%   max_security_risk = 3 forces at least mac+some_logging on any
%%   high-impact (>=5), high-domain non-redundant asset:
%%     c6r1 read: impact=5, DB=3  → needs SP+LP >= 5  (mac+some_logging = 4+1 = 5 ✓)
%%     c8r1 write: impact=4, DB=3 → needs SP+LP >= 4  (mac+no_logging  = 4+0 = 4 ✓)
%%     c7r1: low domain (DB=0)    → always satisfied   (2+0-4-0 = -2 → 0 ≤ 3 ✓)
%%
%% Redundant group (c1-c5, group size 5) — probabilistic model:
%%   Risk = Imp * denorm_prob / 100
%%   Denorm floor = Mu*10 = 250, so minimum risk = Imp * 250/100
%%   For impact=5: minimum = 12 (with any security), max ≈ 15 (mac+no_logging)
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

% Dual-risk budget caps (see header comment for derivation).
system_capability(max_security_risk, 3).   % additive cap: non-redundant components
system_capability(max_avail_risk,   20).   % probabilistic cap: redundant group

% Alias for opt_resource_enc.lp (uses max_bufg, not max_bufgs)
system_capability(max_bufg, 32).
