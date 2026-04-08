%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% bridge_enc.lp
%% Purpose: Enforce the latency constraint after component-scoped feature choice.
%%
%% FIX - Latency constraint not enforced
%%   opt_latency_enc.lp computes asset_latency/3 but never constrains
%%   it against allowable_latency/3. Constraint added here.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% --- Enforce latency budget per asset per operation ---
:- asset(_, A, Action),
   asset_latency(A, Action, Lat),
   allowable_latency(A, Action, MaxLat),
   Lat > MaxLat.
