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
% write (integrity), avail (availability / DoS). For non-redundant
% components the residual-risk model is multiplicative:
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
%   max_avail_risk     — caps the PROBABILISTIC availability risk for redundant
%                        groups.  This is what redundancy architecture controls:
%                        Risk = Imp * denorm_combined_prob * ExploitFactor / 1000.
%
% The two budgets are entirely independent.  A design can violate one, the
% other, or both.  The solver enforces them as separate hard constraints.
%
% Inputs expected from instance/selected files:
%   component/1, asset/3, impact/3          (read, write, and/or avail)
%   exposure/2, realtime_detection/2
%   selected_security/2, selected_realtime/2
%   redundant_group/2
%   domain/2  (untrusted | low | normal | privileged | high | root)
%   exploitability/2  (optional, 1–5; default = 3 neutral)
%   system_capability(max_security_risk, Cap)
%   system_capability(max_avail_risk,    Cap)

% --- Parameters ---
mu(25).
omega(1000).

#show impact/3.
#show asset/3.

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

% --- Original combined probability Exposure*Realtime ---
original_prob(C, Prob) :-
    exposure_score(C, V),
    realtime_score(C, L),
    Prob = V * L.

% --- Normalize to [0, 1000] ---
original_prob_normalized(C, Norm) :-
    component(C),
    original_prob(C, P),
    mu(Mu),
    omega(Omega),
    Norm = (P - Mu) * 1000 / (Omega - Mu).

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

% --- Running normalised partial product ---
partial_norm(G, 1, C, P) :-
    group_rank(G, C, 1),
    original_prob_normalized(C, P).

partial_norm(G, R, C, Norm) :-
    R > 1,
    group_rank(G, C, R),
    original_prob_normalized(C, Pcur),
    Rprev = R - 1,
    partial_norm(G, Rprev, _, Pprev),
    Norm = Pprev * Pcur / 1000.

% --- Combined normalised probability for the group ---
combined_prob_norm(G, Norm) :-
    group_size(G, N),
    partial_norm(G, N, _, Norm).

% --- Map group probability back to each member ---
new_prob_normalized(C, P) :-
    redundant_group(G, C),
    combined_prob_norm(G, P).

% --- Denormalize ---
new_prob_denormalized(C, Denorm) :-
    new_prob_normalized(C, P),
    mu(Mu),
    omega(Omega),
    Denorm = (P * (Omega - Mu) / 1000) + Mu * 10.

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
    component(C),
    in_any_group(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    new_prob_denormalized(C, P),
    exploit_factor(C, EF),
    Risk = Imp * P * EF / 1000.

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

#show exploit_mod/2.
#show exploit_factor/2.

% --- Output ---
#show original_register_risk/4.
#show original_prob/2.
#show original_prob_normalized/2.
#show new_prob_normalized/2.
#show new_prob_denormalized/2.
#show security_risk/4.
#show avail_risk/4.
#show new_risk/4.
#show combined_prob_norm/2.
#show domain_bonus/2.
#show exploit_mod/2.
#show risk_weight/2.
#show weighted_risk/4.
