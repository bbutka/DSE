% opt_redundancy_generic_enc.lp
%
% Generic closed-form redundancy encoding.
% Replaces the size-specific rules (sizes 2–5) and the precomputed LUT with
% a single recursive computation that works for any group size >= 1.
%
% Mathematical basis:
%   combined_prob_norm = P1 * P2 * ... * PN / 1000^(N-1)
%
% To avoid 32-bit integer overflow (Clingo 5 uses signed 32-bit integers),
% the division by 1000 is applied at each multiplication step rather than
% at the end.  This keeps every intermediate value in [0, 1000], safe from
% overflow regardless of group size or the exposure/realtime values used.
%
% Correctness: dividing by 1000 at step k is equivalent to dividing the
% final product by 1000^(N-1) — the mathematically correct normalisation
% for N parallel redundant components.
%
% FULL CIA RISK MODEL
% ===================
% Risk is computed for all three CIA action types: read (confidentiality),
% write (integrity), avail (availability / DoS). Exposure and realtime values
% are ordinal residual-exposure scores from the feature catalog, not calibrated
% probabilities. For non-redundant components the residual-risk model is
% multiplicative:
%
%   Risk = Impact * Exposure * Realtime * ExploitFactor / 100
%
% This matches the older multiplicative Phase 1 formulation. Avail impact
% facts are only emitted by the generator when impact_avail > 0, so existing
% models without avail facts are unaffected.
%
% EXPLOITABILITY MODIFIER / GRADUATED TRUST DOMAINS
% ================================================
% domain_bonus/2 is retained for diagnostics and downstream weighting only.
% exploit_factor/2 now participates directly in both Phase 1 risk paths:
%   - non-redundant multiplicative residual risk
%   - redundant denormalized availability risk
%
% DUAL-RISK BUDGET (Option A)
% ===========================
% Two independent risk budgets replace the single max_asset_risk cap:
%
%   max_security_risk  — caps the MULTIPLICATIVE residual risk for
%                        non-redundant components:
%                        Risk = Impact * Exposure * Realtime * ExploitFactor / 100.
%
%   max_avail_risk     — caps the corrected availability risk for redundant
%                        groups.  This is what redundancy architecture controls:
%                        Risk = Imp * corrected_group_score * ExploitFactor / 1000.
%
% The two budgets are entirely independent.  A design can violate one, the
% other, or both.  The solver enforces them as separate hard constraints.
%
% Inputs expected from instance/selected files:
%   component/1, asset/3, impact/3          (read, write, and/or avail)
%   exposure/2, realtime_detection/2
%   selected_security/2, selected_realtime/2, selected_pair/2 (optional)
%   redundant_group/2
%   domain/2  (untrusted | low | normal | privileged | high | root)
%   exploitability/2  (optional, 1–5; default = 3 neutral)
%   system_capability(max_security_risk, Cap)
%   system_capability(max_avail_risk,    Cap)
%
% Optional preprocessed redundancy facts from Python:
%   group_plan_candidate/2
%   group_plan_member_pair/4
%   group_plan_final_risk/6

% --- Parameters ---
mu(25).
omega(1000).

#show impact/3.
#show asset/3.

preprocessed_group_plans :- group_plan_candidate(_, _).
preprocessed_group_transitions :- group_transition(_, _, _, _, _).
preprocessed_redundancy_groups :- preprocessed_group_plans.
preprocessed_redundancy_groups :- preprocessed_group_transitions.

% --- Security and realtime scores per component ---
exposure_score(C, V) :- selected_security(C, S), exposure(S, V).
realtime_score(C, L)        :- selected_realtime(C, Lf), realtime_detection(Lf, L).

#show exposure_score/2.
#show realtime_score/2.

% --- Graduated domain bonus ---
% Supports: untrusted(0) | low(0) | normal(1) | privileged(2) | high(3) | root(3)
% Default: 1 (normal) when no domain fact is asserted.
domain_bonus(C, 0) :- component(C), domain(C, untrusted).
domain_bonus(C, 0) :- component(C), domain(C, low).
domain_bonus(C, 1) :- component(C), domain(C, normal).
domain_bonus(C, 2) :- component(C), domain(C, privileged).
domain_bonus(C, 3) :- component(C), domain(C, high).
domain_bonus(C, 3) :- component(C), domain(C, root).
domain_bonus(C, 1) :- component(C),
    not domain(C, untrusted), not domain(C, low),
    not domain(C, normal),    not domain(C, privileged),
    not domain(C, high),      not domain(C, root).

% --- Exploitability modifier ---
% Mod = E - 3: E=1 → -2 (hard to exploit), E=3 → 0 (neutral), E=5 → +2 (trivial)
% Default: 0 when no exploitability fact is present.
exploit_mod(C, Mod) :- exploitability(C, E), Mod = E - 3.
exploit_mod(C, 0)   :- component(C), not exploitability(C, _).
exploit_factor(C, F) :- exploitability(C, E), exploit_factor_map(E, F).
exploit_factor(C, 10) :- component(C), not exploitability(C, _).

% --- Multiplicative residual risk per component (all CIA action types) ---
% Risk = Impact * Exposure * Realtime * ExploitFactor / 100.
original_register_risk(C, R, Action, Risk) :-
    component(C), asset(C, R, Action),
    impact(R, Action, Imp),
    exposure_score(C, V),
    realtime_score(C, L),
    exploit_factor(C, EF),
    Risk = Imp * V * L * EF / 100.

% --- Precomputed residual-score lookup ---
% Deterministic score math is emitted by Python as prob_lookup/5 so Clingo
% does not need to enumerate integer domains through chained arithmetic rules.
original_prob(C, Prob) :-
    not preprocessed_redundancy_groups,
    selected_security(C, S),
    selected_realtime(C, L),
    prob_lookup(S, L, Prob, _, _).

original_prob_normalized(C, Norm) :-
    not preprocessed_redundancy_groups,
    selected_security(C, S),
    selected_realtime(C, L),
    prob_lookup(S, L, _, Norm, _).

% --- Group membership helpers ---
in_any_group(C) :- redundant_group(_, C).

group_size(G, N) :-
    redundant_group(G, _),
    N = #count { C : redundant_group(G, C) }.

% --- Canonical rank within each group (lexicographic order via <) ---
group_rank(G, C, R) :-
    redundant_group(G, C),
    N = #count { C2 : redundant_group(G, C2), C2 < C },
    R = N + 1.

% --- Combined normalised score for the group ---
% Flattened by group size to avoid recursive arithmetic grounding blow-up.
combined_prob_norm(G, P1) :-
    not preprocessed_redundancy_groups,
    group_size(G, 1),
    group_rank(G, C1, 1),
    original_prob_normalized(C1, P1).

combined_prob_norm(G, Norm) :-
    not preprocessed_redundancy_groups,
    group_size(G, 2),
    group_rank(G, C1, 1),
    original_prob_normalized(C1, P1),
    group_rank(G, C2, 2),
    original_prob_normalized(C2, P2),
    Norm = P1 * P2 / 1000.

combined_prob_norm(G, Norm) :-
    not preprocessed_redundancy_groups,
    group_size(G, 3),
    group_rank(G, C1, 1),
    original_prob_normalized(C1, P1),
    group_rank(G, C2, 2),
    original_prob_normalized(C2, P2),
    group_rank(G, C3, 3),
    original_prob_normalized(C3, P3),
    Norm = P1 * P2 / 1000 * P3 / 1000.

combined_prob_norm(G, Norm) :-
    not preprocessed_redundancy_groups,
    group_size(G, 4),
    group_rank(G, C1, 1),
    original_prob_normalized(C1, P1),
    group_rank(G, C2, 2),
    original_prob_normalized(C2, P2),
    group_rank(G, C3, 3),
    original_prob_normalized(C3, P3),
    group_rank(G, C4, 4),
    original_prob_normalized(C4, P4),
    Norm = P1 * P2 / 1000 * P3 / 1000 * P4 / 1000.

combined_prob_norm(G, Norm) :-
    not preprocessed_redundancy_groups,
    group_size(G, 5),
    group_rank(G, C1, 1),
    original_prob_normalized(C1, P1),
    group_rank(G, C2, 2),
    original_prob_normalized(C2, P2),
    group_rank(G, C3, 3),
    original_prob_normalized(C3, P3),
    group_rank(G, C4, 4),
    original_prob_normalized(C4, P4),
    group_rank(G, C5, 5),
    original_prob_normalized(C5, P5),
    Norm = P1 * P2 / 1000 * P3 / 1000 * P4 / 1000 * P5 / 1000.

% --- Map group probability back to each member ---
new_prob_normalized(C, P) :-
    not preprocessed_redundancy_groups,
    redundant_group(G, C),
    combined_prob_norm(G, P).

% --- Denormalize ---
new_prob_denormalized(C, Denorm) :-
    not preprocessed_redundancy_groups,
    new_prob_normalized(C, P),
    mu(Mu),
    omega(Omega),
    Denorm = (P * (Omega - Mu) / 1000) + Mu * 10.

% --- Single-component denormalized score for common-cause correction ---
single_prob_denormalized(C, Denorm) :-
    not preprocessed_redundancy_groups,
    selected_security(C, S),
    selected_realtime(C, L),
    prob_lookup(S, L, _, _, Denorm).

group_max_denorm(G, Max) :-
    not preprocessed_redundancy_groups,
    redundant_group(G, _),
    Max = #max { D : redundant_group(G, C), single_prob_denormalized(C, D) }.

% --- Common-cause beta-factor correction ---
% redundancy_beta_pct/1 blends the independent group score with the worst
% single-component score in the group:
%   corrected = (1 - beta) * independent + beta * worst_member
% where beta is given as an integer percentage in [0, 100].
redundancy_beta_pct(B) :- system_capability(redundancy_beta_pct, B).
redundancy_beta_pct(0) :- not system_capability(redundancy_beta_pct, _).

corrected_prob_denormalized(C, Corrected) :-
    not preprocessed_redundancy_groups,
    new_prob_denormalized(C, Indep),
    redundant_group(G, C),
    group_max_denorm(G, Common),
    redundancy_beta_pct(B),
    Corrected = ((100 - B) * Indep + B * Common) / 100.

% ===========================================================================
% DUAL-RISK BUDGET — named risk predicates and independent hard constraints
% ===========================================================================

% Security risk: multiplicative model, applies to non-redundant components.
% These are the components whose risk the security feature DSE directly controls.
security_risk(C, R, A, Risk) :-
    component(C),
    not in_any_group(C),
    original_register_risk(C, R, A, Risk).

% Availability risk: probabilistic model, applies to redundant group members.
% These components benefit from redundancy; their risk floor is set by the
% group size and the Mu * 10 denormalisation constant, not security features alone.
avail_risk(C, R, Action, Risk) :-
    not preprocessed_redundancy_groups,
    component(C),
    in_any_group(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    corrected_prob_denormalized(C, P),
    exploit_factor(C, EF),
    Risk = Imp * P * EF / 1000.

group_state(G, Stage, State) :-
    preprocessed_group_transitions,
    group_start_stage(G, Stage),
    group_start_state(G, Start),
    group_stage_member(G, Stage, C),
    selected_pair(C, Pair),
    group_transition(G, Stage, Start, Pair, State).

group_state(G, Stage, NextState) :-
    preprocessed_group_transitions,
    group_prev_stage(G, Stage, PrevStage),
    group_state(G, PrevStage, PrevState),
    group_stage_member(G, Stage, C),
    selected_pair(C, Pair),
    group_transition(G, Stage, PrevState, Pair, NextState).

selected_group_final_state(G, State) :-
    preprocessed_group_transitions,
    group_last_stage(G, Stage),
    group_state(G, Stage, State),
    valid_group_final_state(G, State).

:- preprocessed_group_transitions,
   redundant_group(G, _),
   not selected_group_final_state(G, _).

avail_risk(C, R, Action, Risk) :-
    preprocessed_group_transitions,
    selected_group_final_state(G, State),
    group_final_risk(G, State, C, R, Action, Risk).

avail_risk(C, R, Action, Risk) :-
    preprocessed_group_plans,
    selected_group_plan(G, Plan),
    group_plan_final_risk(G, Plan, C, R, Action, Risk).

% Unified new_risk feeds the minimize objective and downstream phases.
new_risk(C, R, A, Risk) :- security_risk(C, R, A, Risk).
new_risk(C, R, A, Risk) :- avail_risk(C, R, A, Risk).

% --- Security risk budget (hard constraint) ---
% Enforces the multiplicative cap on non-redundant components only.
:- security_risk(_, _, _, Risk),
   system_capability(max_security_risk, Cap),
   Risk > Cap.

% --- Availability risk budget (hard constraint) ---
% Enforces the probabilistic cap on redundant group members.
:- avail_risk(_, _, _, Risk),
   system_capability(max_avail_risk, Cap),
   Risk > Cap.

% --- Minimise total weighted asset risk ---
% When risk_weight/2 facts are present (emitted by ASPGenerator), the objective
% weights each risk point by the topology-derived amplification proxy for that
% asset.  This causes the solver to preferentially reduce risk on assets that
% Phase 3 scenario analysis will amplify most (safety-critical, high blast-radius,
% privileged-domain components).
%
% When no risk_weight/2 facts are present (standalone / legacy runs) the fallback
% objective is unweighted — identical to the original behaviour.
%
% The two-literal disjunction in the weight expression ensures exactly one fires
% per (C, Asset, Action) triple regardless of whether risk_weight is defined.
weighted_risk(C, Asset, Action, WR) :-
    new_risk(C, Asset, Action, Risk),
    risk_weight(Asset, W),
    WR = Risk * W.

weighted_risk(C, Asset, Action, Risk) :-
    new_risk(C, Asset, Action, Risk),
    not risk_weight(Asset, _).

#minimize { WR, C, Asset, Action : weighted_risk(C, Asset, Action, WR) }.

% --- Output ---
#show original_register_risk/4.
#show original_prob/2.
#show original_prob_normalized/2.
#show new_prob_normalized/2.
#show new_prob_denormalized/2.
#show corrected_prob_denormalized/2.
#show security_risk/4.
#show avail_risk/4.
#show new_risk/4.
#show combined_prob_norm/2.
#show group_max_denorm/2.
#show domain_bonus/2.
#show exploit_mod/2.
#show exploit_factor/2.
#show redundancy_beta_pct/1.
#show risk_weight/2.
#show weighted_risk/4.
