%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% bridge_enc.lp
%% Purpose: Two fixes needed when combining HOST26 encodings
%%
%% FIX 1 — Selection index mismatch
%%   init_enc.lp creates:      selected_security(Component, Feature)
%%   opt_*_enc.lp files use:   selected_security(AssetReg,  Feature)
%%   e.g. init_enc produces selected_security(c1, zero_trust)
%%        opt_security_enc needs selected_security(c1r1, zero_trust)
%%   Bridge: derive asset-level selection from component-level.
%%
%% FIX 2 — Latency constraint not enforced
%%   opt_latency_enc.lp computes asset_latency/3 but never constrains
%%   it against allowable_latency/3. Constraint added here.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% --- FIX 1: Propagate component-level selection to asset level ---
% asset(Component, AssetReg, Action) — AssetReg is second argument
selected_security(A, F) :- asset(C, A, _), selected_security(C, F).
selected_logging(A, L)  :- asset(C, A, _), selected_logging(C, L).

% --- FIX 2: Enforce latency budget per asset per operation ---
:- asset(_, A, Action),
   asset_latency(A, Action, Lat),
   allowable_latency(A, Action, MaxLat),
   Lat > MaxLat.
