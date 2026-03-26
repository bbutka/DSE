% tc9_lut_adapter_example.lp
%
% Example adapter layer for using the LUT + interpolation in a testCase9-style
% redundancy calculation.
%
% Include:
%   #include "clingo_ln_lookup_table_1_to_1e9.lp".
%   #include "clingo_ln_interp_rules_1_to_1e9.lp".
%
% Replace the example member_prob_scaled/2 facts with your actual predicates.

#include "clingo_ln_lookup_table_1_to_1e9.lp".
#include "clingo_ln_interp_rules_1_to_1e9.lp".

prob_scale(1000000).

% ----------------------------------------------------------------------
% Example inputs
% Replace these with your actual dynamic TC9 probability-producing rules.
% ----------------------------------------------------------------------

redundancy_group(g1).
group_member(g1,c1).
group_member(g1,c2).
group_member(g1,c3).
group_member(g1,c4).
group_member(g1,c5).

% Example scaled probabilities in [1, 1_000_000]
member_prob_scaled(c1,875000).
member_prob_scaled(c2,920000).
member_prob_scaled(c3,950000).
member_prob_scaled(c4,900000).
member_prob_scaled(c5,980000).

% ----------------------------------------------------------------------
% Dynamic LUT queries
% ----------------------------------------------------------------------

ln_query(M, X) :-
    member_prob_scaled(M, X),
    X >= 1, X <= 1000000000.

% ----------------------------------------------------------------------
% Group aggregation with sum of logs
% ----------------------------------------------------------------------

group_ln_sum(G, Sum) :-
    redundancy_group(G),
    Sum = #sum { Ln, M : group_member(G, M), ln_interp(M, Ln) }.

% Count members, if needed for downstream normalization/annotation
group_size(G, N) :-
    redundancy_group(G),
    N = #count { M : group_member(G, M) }.

% Example ordering predicate: "lower log-sum" means lower product
group_rank_value(G, Sum) :- group_ln_sum(G, Sum).

% ----------------------------------------------------------------------
% Optional guards for zero or missing values
% ----------------------------------------------------------------------

invalid_member_prob(M) :-
    group_member(_, M),
    not member_prob_scaled(M, _).

invalid_member_prob(M) :-
    member_prob_scaled(M, X),
    X < 1.

#show member_prob_scaled/2.
#show ln_interp/2.
#show group_ln_sum/2.
#show group_size/2.
#show invalid_member_prob/1.
