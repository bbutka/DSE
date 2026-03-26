% --- Parameters ---
mu(50).       % Scaled by 10 to avoid decimals (e.g., 0.5 * 10 = 5)
omega(1000).  % Scaled similarly (e.g., 10 * 10 = 100)

% --- Vulnerability scores scaled by 10 ---
vulnerability(mac, 30).
% Add other vulnerabilities here if needed

% --- Logging scores scaled by 10 ---
logging(some_logging, 10).
% Add other logging features here if needed

% --- Components ---
component(c1).
component(c2).
component(c3).

% --- Impacts (max_read_impact and max_write_impact), scaled by 10 if needed ---
max_read_impact(c1, 10).
max_write_impact(c1, 50).

max_read_impact(c2, 50).
max_write_impact(c2, 20).

max_read_impact(c3, 30).
max_write_impact(c3, 30).

% --- Selected security and logging for each component ---
selected_security(C, mac) :- component(C).
selected_logging(C, some_logging) :- component(C).

% --- Calculate vulnerability and logging score per component ---
vulnerability_score(C, V) :- selected_security(C, S), vulnerability(S, V).
logging_score(C, L) :- selected_logging(C, Lf), logging(Lf, L).

% --- Original read and write risk calculations ---
original_read_risk(C, Risk) :-
    component(C),
    max_read_impact(C, RImp),
    vulnerability_score(C, V),
    logging_score(C, L),
    Risk = RImp * V * L / 1000.   % divide by scale factor to keep consistent scale

original_write_risk(C, Risk) :-
    component(C),
    max_write_impact(C, WImp),
    vulnerability_score(C, V),
    logging_score(C, L),
    Risk = WImp * V * L / 1000.

% --- Original combined probability (vuln * logging), scaled ---
original_prob(C, Prob) :-
    vulnerability_score(C, V),
    logging_score(C, L),
    Prob = V * L.



% --- Normalize original_prob ---
original_prob_normalized(C, Norm) :-
    original_prob(C, P),
    mu(Mu),
    omega(Omega),
    NormNum = (P - Mu)*1000 / (Omega - Mu), % scaled normalized probability (integer)
    Norm = NormNum.

% --- Define redundancy groups ---
redundant_group(1, c1).
redundant_group(1, c2).
redundant_group(1, c3).
% Add more groups as needed

% --- Calculate combined normalized probability for a redundant group of length 3 ---
combined_prob_norm(G, P) :-
    redundant_group(G, c1),
    redundant_group(G, c2),
    redundant_group(G, c3),
    original_prob_normalized(c1, P1),
    original_prob_normalized(c2, P2),
    original_prob_normalized(c3, P3),
    P = (P1 * P2 * P3)/100000.

% --- Assign combined normalized probability to each component in the group ---
in_any_group(C) :- redundant_group(_, C).

new_prob_normalized(C, P) :-
    redundant_group(G, C),
    combined_prob_norm(G, P).

% --- Denormalize new probabilities ---
new_prob_denormalized(C, Denorm) :-
    new_prob_normalized(C, P),
    mu(Mu),
    omega(Omega),
    Denorm = (P * (Omega - Mu)/1000)+Mu*10. % To expand the number, remove from division, add to multiplication

% --- Calculate new read/write risks based on denormalized new probabilities ---
new_read_risk(C, Risk) :-
    component(C),
    max_read_impact(C, RImp),
    new_prob_denormalized(C, P),
    Risk = RImp * P / 1000.

new_write_risk(C, Risk) :-
    component(C),
    max_write_impact(C, WImp),
    new_prob_denormalized(C, P),
    Risk = WImp * P / 1000.

% --- Display the results ---
#show original_read_risk/2.
#show original_write_risk/2.
#show original_prob/2.
#show original_prob_normalized/2.
#show new_prob_normalized/2.
#show new_prob_denormalized/2.
#show new_read_risk/2.
#show new_write_risk/2.
#show combined_prob_norm/2.

% --- Helpers ---
