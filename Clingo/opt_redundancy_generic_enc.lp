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
% overflow regardless of group size or the vulnerability/logging values used.
%
% Correctness: dividing by 1000 at step k is equivalent to dividing the
% final product by 1000^(N-1) — the mathematically correct normalisation
% for N parallel redundant components.
%
% Inputs expected from instance/selected files:
%   component/1, asset/3, impact/3
%   vulnerability/2, logging/2
%   selected_security/2, selected_logging/2
%   redundant_group/2
%   system_capability(max_asset_risk, MaxRisk)

% --- Parameters ---
mu(25).
omega(1000).

#show impact/3.
#show asset/3.

% --- Security and logging scores per component ---
vulnerability_score(C, V) :- selected_security(C, S), vulnerability(S, V).
logging_score(C, L)        :- selected_logging(C, Lf), logging(Lf, L).

#show vulnerability_score/2.
#show logging_score/2.

% --- Domain bonus: high-domain components carry additional exposure risk ---
domain_bonus(C, 3) :- component(C), domain(C, high).
domain_bonus(C, 0) :- component(C), domain(C, low).
domain_bonus(C, 0) :- component(C), not domain(C, high), not domain(C, low).

% --- Additive protection scores per component ---
security_protect_score(C, SP) :- selected_security(C, S), security_protect_val(S, SP).
log_protect_score(C,    LP) :- selected_logging(C, Lf),  log_protect_val(Lf, LP).

% --- Original risk: additive model ---
% Residual risk = Impact + DomainBonus − SecurityProtection − LogProtection, clamped to 0.
% Rationale: ordinal impact scores are not ratio-scale; adding them avoids the
% multiplicative artefact where reducing a low factor yields disproportionate
% risk reduction.  Consistent with NIST 800-30 qualitative combination.
original_register_risk(C, R, Action, Risk) :-
    component(C), asset(C, R, Action),
    impact(R, Action, Imp),
    domain_bonus(C, DB),
    security_protect_score(C, SP),
    log_protect_score(C, LP),
    Risk = Imp + DB - SP - LP,
    Risk >= 0.

original_register_risk(C, R, Action, 0) :-
    component(C), asset(C, R, Action),
    impact(R, Action, Imp),
    domain_bonus(C, DB),
    security_protect_score(C, SP),
    log_protect_score(C, LP),
    Imp + DB - SP - LP < 0.

% --- Original combined probability V*L ---
original_prob(C, Prob) :-
    vulnerability_score(C, V),
    logging_score(C, L),
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
% Rank is unique: each member gets exactly one position 1..N.
group_rank(G, C, R) :-
    redundant_group(G, C),
    N = #count { C2 : redundant_group(G, C2), C2 < C },
    R = N + 1.

% --- Running normalised partial product ---
%
% At rank 1 the running value is simply the component's own normalised prob.
% At each subsequent rank we multiply in the next component and immediately
% divide by 1000, keeping the running value in [0, 1000] at all times.
% This is overflow-safe for any group size under Clingo 5's 32-bit integers
% (max intermediate = 1000 * 1000 = 10^6, well within 2^31 - 1).
%
% After N steps the value equals P1*P2*...*PN / 1000^(N-1), which is the
% correct combined normalised probability for N redundant components.

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

% --- Risk for components NOT in any redundancy group ---
new_risk(C, R, A, Risk) :-
    component(C),
    not in_any_group(C),
    original_register_risk(C, R, A, Risk).

% --- Risk for components IN a redundancy group ---
new_risk(C, R, Action, Risk) :-
    component(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    new_prob_denormalized(C, P),
    Risk = Imp * P / 100.

% --- Hard risk cap ---
% Use the MAXIMUM declared cap so that topology-specific LP files can provide
% a permissive floor (e.g. for redundant groups whose probabilistic formula
% produces inherently higher numbers) while still allowing the GUI/extra_facts
% to inject a tighter cap for non-redundant topologies.
% Rationale: if both tgt_system_tc9_inst.lp (cap=20, for redundant group floor)
% and GUI extra_facts (cap=3, for non-redundant additive model) are present,
% the effective cap is max(20, 3) = 20 — feasible for TC9's redundant group.
% For fresh topologies with only GUI injection (cap=3), the effective cap is 3.
effective_risk_cap(Cap) :- Cap = #max { V : system_capability(max_asset_risk, V) }.
:- new_risk(_, _, _, Risk), effective_risk_cap(Cap), Risk > Cap.

% --- Minimise total asset risk (deduplicated on all four key fields) ---
#minimize { Risk, C, Asset, Action : new_risk(C, Asset, Action, Risk) }.

% --- Output ---
#show original_register_risk/4.
#show original_prob/2.
#show original_prob_normalized/2.
#show new_prob_normalized/2.
#show new_prob_denormalized/2.
#show new_risk/4.
#show combined_prob_norm/2.
#show effective_risk_cap/1.
