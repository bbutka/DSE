% --- Parameters ---
mu(25).       % Scaled by 10 to avoid decimals (e.g., 0.5 * 10 = 5)
omega(1000).  % Scaled similarly (e.g., 10 * 10 = 100)

#show impact/3.
#show asset/3.

% --- Selected security and logging for each component ---
%selected_security(C, zero_trust) :- component(C).
%selected_logging(C, zero_trust_logger) :- component(C).

% --- Calculate vulnerability and logging score per component ---
vulnerability_score(C, V) :- selected_security(C, S), vulnerability(S, V).
logging_score(C, L) :- selected_logging(C, Lf), logging(Lf, L).

#show vulnerability_score/2.
#show logging_score/2.

% --- Original read and write risk calculations ---
original_register_risk(C, R, Action, Risk) :-
    component(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    vulnerability_score(C, V),
    logging_score(C, L),
    Risk = Imp * V * L / 10.

%original_write_risk(C, R, Risk) :-
%    component(C),
%    asset(C, R, write),
%    impact(R, write, WImp),
%    vulnerability_score(C, V),
%    logging_score(C, L),
%    Risk = WImp * V * L / 100.
% --- Original combined probability (vuln * logging), scaled ---

original_prob(C, Prob) :-
    vulnerability_score(C, V),
    logging_score(C, L),
    Prob = V * L.

% --- Normalize original_prob ---
original_prob_normalized(C, Norm) :-
    component(C),
    original_prob(C, P),
    mu(Mu),
    omega(Omega),
    NormNum = (P - Mu)*1000 / (Omega - Mu), % scaled normalized probability (integer)
    Norm = NormNum.



% --- Count group size ---
in_any_group(C) :- redundant_group(_, C).
group_size(G, N) :-
    redundant_group(G, _),
    N = #count { C : redundant_group(G, C) }.

% --- Combined normalized probability for groups of size 2 ---
combined_prob_norm(G, P) :-
    group_size(G, 2),
    redundant_group(G, C1),
    redundant_group(G, C2),
    C1 < C2,
    original_prob_normalized(C1, P1),
    original_prob_normalized(C2, P2),
    P = (P1 * P2) / 100000.

% --- Combined normalized probability for groups of size 3 ---
combined_prob_norm(G, P) :-
    group_size(G, 3),
    redundant_group(G, C1),
    redundant_group(G, C2),
    redundant_group(G, C3),
    C1 < C2, C2 < C3,
    original_prob_normalized(C1, P1),
    original_prob_normalized(C2, P2),
    original_prob_normalized(C3, P3),
    P = (P1 * P2 * P3) / 100000.

% --- Combined normalized probability for groups of size 4 ---
combined_prob_norm(G, P) :-
    group_size(G, 4),
    redundant_group(G, C1),
    redundant_group(G, C2),
    redundant_group(G, C3),
    redundant_group(G, C4),
    C1 < C2, C2 < C3, C3 < C4,
    original_prob_normalized(C1, P1),
    original_prob_normalized(C2, P2),
    original_prob_normalized(C3, P3),
    original_prob_normalized(C4, P4),
    P = (P1 * P2 * P3 * P4) / 100000.

% --- Combined normalized probability for groups of size 5 ---
combined_prob_norm(G, P) :-
    group_size(G, 5),
    redundant_group(G, C1),
    redundant_group(G, C2),
    redundant_group(G, C3),
    redundant_group(G, C4),
    redundant_group(G, C5),
    C1 < C2, C2 < C3, C3 < C4, C4 < C5,
    original_prob_normalized(C1, P1),
    original_prob_normalized(C2, P2),
    original_prob_normalized(C3, P3),
    original_prob_normalized(C4, P4),
    original_prob_normalized(C5, P5),
    P = (P1 * P2 * P3 * P4 * P5) / 100000000.


new_prob_normalized(C, P) :-
    redundant_group(G, C),
    combined_prob_norm(G, P).

% --- Denormalize new probabilities ---
new_prob_denormalized(C, Denorm) :-
    new_prob_normalized(C, P),
    mu(Mu),
    omega(Omega),
    Denorm = (P * (Omega - Mu)/1000)+Mu*10. % To expand the number, remove from division, add to multiplication

% --- For components NOT in any redundancy group, use original probabilities ---
new_risk(C,R,A, P) :-
    component(C),
    not in_any_group(C),
    original_register_risk(C, R, A, P).


%new_prob_denormalized(C, Denorm) :-
%    component(C),
%    not in_any_group(C),
%    original_prob_denormalized(C, Denorm).

% --- Calculate new read/write risks based on denormalized new probabilities ---
new_risk(C, R, Action, Risk) :-
    component(C),
    asset(C, R, Action),
    impact(R, Action, Imp),
    new_prob_denormalized(C, P),
    Risk = Imp * P / 100.

% Minimize Total Asset Risk --------------------------------

% Ensure that the risk for each asset does not exceed the maximum allowable risk
%:-original_register_risk(_, _, Risk), system_capability(max_asset_risk, MaxRisk), Risk > MaxRisk.
%#show original_register_risk/3.
:-new_risk(_,_, _, Risk), system_capability(max_asset_risk, MaxRisk), Risk > MaxRisk.
#show new_risk/4.


%#minimize { Risk, Asset :original_register_risk(Asset, Action, Risk) }.
#minimize { Risk, Asset :new_risk(C,Asset, Action, Risk) }.

% End Minimize Total Asset Risk ----------------------------

% --- Display the results ---
#show original_register_risk/4.
#show original_prob/2.
#show original_prob_normalized/2.
#show new_prob_normalized/2.
#show new_prob_denormalized/2.
#show new_risk/4.
#show combined_prob_norm/2.

% --- Helpers ---