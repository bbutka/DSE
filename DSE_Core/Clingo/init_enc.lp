%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: [Author]
% File: Initialize DSE Encoding
% Last Edited: 4/8/2026
% Purpose: Initialize the DSE with required constraints
%          Specifically, allow only one feature per receiver/component
%
% Design note:
%   Phase 1 features are selected once per receiver/component.
%   Resource accounting, risk scoring, and the Python backends are all
%   component-scoped, so grounding the choice over asset(C,_,_) only
%   duplicates equivalent decisions and inflates the TC9 ground program.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initialization -------------------------------------------

% Optional preprocessed pair mode for ASP parity/comparison runs.
% When Python emits candidate_pair/2 facts, Clingo chooses among those
% pre-filtered security/realtime combinations instead of grounding the full
% cross-product.
has_candidate_pairs :- candidate_pair(_, _).
group_has_plan(G) :- group_plan_candidate(G, _).
group_plan_member(C) :- group_plan_member_pair(_, _, C, _).

1 { selected_group_plan(G, Plan) : group_plan_candidate(G, Plan) } 1 :-
    group_has_plan(G).

selected_pair(C, P) :-
    selected_group_plan(G, Plan),
    group_plan_member_pair(G, Plan, C, P).

1 { selected_pair(C, P) : candidate_pair(C, P) } 1 :-
    receiver(C),
    has_candidate_pairs,
    not group_plan_member(C).

selected_security(C, F) :-
    selected_pair(C, P),
    pair_security(P, F).

selected_realtime(C, L) :-
    selected_pair(C, P),
    pair_realtime(P, L).

% Compatibility mode: if no candidate pairs are injected, keep the original
% feature-level choice encoding.
1 { selected_realtime(C, L) : realtime_feature(L) } 1 :-
    receiver(C),
    not has_candidate_pairs.

1 { selected_security(C, F) : security_feature(F) } 1 :-
    receiver(C),
    not has_candidate_pairs.

#show selected_realtime/2.
#show selected_security/2.

% End Initialization ---------------------------------------
