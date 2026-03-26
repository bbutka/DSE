% opt_redundancy_lut_enc.lp
%
% Phase 1 tc9 variant that avoids the overflow-prone redundancy product.
% It keeps the original component/security/logging/resource structure, but
% replaces the grouped probability multiplication with additive log weights.
%
% The pair-level log weights are generated from the supplied LUT pack and
% stored in tc9_pair_log_facts.lp so the runtime search stays small.

#include "tc9_pair_log_facts.lp".

mu(25).
omega(1000).
#show impact/3.
#show asset/3.

% --- Per-component vulnerability / logging scores ---
vulnerability_score(C, V) :-
    component(C),
    selected_security(C, S),
    vulnerability(S, V).

logging_score(C, L) :-
    component(C),
    selected_logging(C, Lf),
    logging(Lf, L).

#show vulnerability_score/2.
#show logging_score/2.

% --- Original per-asset risk, still exact and small enough to keep in ASP ---
original_register_risk(C, R, Action, Risk) :-
    component(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    vulnerability_score(C, V),
    logging_score(C, L),
    Risk = Imp * V * L / 10.

original_prob(C, Prob) :-
    component(C),
    vulnerability_score(C, V),
    logging_score(C, L),
    Prob = V * L.

% ----------------------------------------------------------------------
% Pair-level probabilities / log weights from the generated fact table
% ----------------------------------------------------------------------

member_prob_scaled(C, Scaled) :-
    component(C),
    selected_security(C, S),
    selected_logging(C, L),
    pair_prob_scaled(S, L, Scaled).

member_log_weight(C, Weight) :-
    component(C),
    selected_security(C, S),
    selected_logging(C, L),
    pair_log_weight(S, L, Weight).

#show original_prob/2.
#show member_prob_scaled/2.
#show member_log_weight/2.

% ----------------------------------------------------------------------
% Group structure and log-sum aggregation
% ----------------------------------------------------------------------

in_any_group(C) :- redundant_group(_, C).

group_size(G, N) :-
    redundant_group(G, _),
    N = #count { C : redundant_group(G, C) }.

group_member_ln(G, C, Ln) :-
    redundant_group(G, C),
    member_log_weight(C, Ln).

group_ln_sum(G, Sum) :-
    redundant_group(G, _),
    Sum = #sum { Ln, C : group_member_ln(G, C, Ln) }.

#show group_size/2.
#show group_member_ln/3.
#show group_ln_sum/2.

% ----------------------------------------------------------------------
% Standalone risks remain exact in ASP because they do not create the large
% chained intermediate product that caused the tc9 overflow.
% ----------------------------------------------------------------------

standalone_new_risk(C, R, Action, Risk) :-
    component(C),
    not in_any_group(C),
    original_register_risk(C, R, Action, Risk).

new_risk(C, R, Action, Risk) :-
    standalone_new_risk(C, R, Action, Risk).

#show standalone_new_risk/4.
#show new_risk/4.

% Keep the original per-asset cap for standalone components.
:- standalone_new_risk(_, _, _, Risk),
   system_capability(max_asset_risk, MaxRisk),
   Risk > MaxRisk.

% ----------------------------------------------------------------------
% Objective
%
% Priority 9: minimize grouped compromise tendency using additive log weights
% Priority 8: tie-break grouped members by their scaled normalized probability
% Priority 7: minimize exact standalone risk
% Priority 6..1: mirror the resource / power tie-break direction used by the
% benchmark scripts so the optimum set stays small enough to inspect.
%
% Python finishes exact grouped probabilities and total risk afterward.
% ----------------------------------------------------------------------

#minimize { Ln@9, C : in_any_group(C), member_log_weight(C, Ln) }.
#minimize { Scaled@8, C : in_any_group(C), member_prob_scaled(C, Scaled) }.
#minimize { Risk@7, Asset, Action : standalone_new_risk(_, Asset, Action, Risk) }.
#minimize { Total@6 : total_luts_used(Total) }.
#minimize { Total@5 : total_ffs_used(Total) }.
#minimize { Total@4 : total_dsps_used(Total) }.
#minimize { Total@3 : total_lutram_used(Total) }.
#minimize { Total@2 : total_bram_used(Total) }.
#minimize { Total@1 : total_power_used(Total) }.
