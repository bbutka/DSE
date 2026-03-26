%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% File: Clingo/topology_enc.lp
% Purpose: Derive topology predicates from link/3 and
%          node_zone/2 facts declared in a test case.
%          Provides reachability, blast radius, and
%          cross-domain link detection.
%
% Stratification proof:
%   adjacent/2        - stratum 0 (positive over facts)
%   active_adjacent/2 - stratum 1 (NAF over failed/1 facts)
%   reachable/2       - stratum 1 (positive recursive over adjacent)
%   active_reachable/2- stratum 2 (positive recursive over active_adjacent)
%   blast_radius/2    - stratum 3 (aggregate over active_reachable)
%   asset_reachable/2 - stratum 3 (positive over active_reachable)
%   cross_domain_link - stratum 0 (positive + built-in != over facts)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% --- Undirected adjacency ---
% We model connectivity as bidirectional for threat analysis:
% an attacker controlling a node can initiate or intercept
% traffic in either direction on any attached link.
adjacent(X, Y) :- link(X, Y, _).
adjacent(X, Y) :- link(Y, X, _).

% --- Active adjacency (excludes failed nodes) ---
% Used for availability analysis: a failed node cannot
% be traversed when checking asset reachability.
% NAF over failed/1 which are ground facts injected per scenario.
% In the baseline (no failed/1 facts), active_adjacent = adjacent.
active_adjacent(X, Y) :- adjacent(X, Y), not failed(X), not failed(Y).

% --- Full reachability (ignores failures) ---
% Used for threat surface analysis: even a dormant/failed node
% may have been pre-compromised before failure.
reachable(X, Y) :- adjacent(X, Y).
reachable(X, Z) :- reachable(X, Y), adjacent(Y, Z).

% --- Active reachability (respects failures) ---
% Used for availability analysis: can component X still be
% reached through the live (non-failed) portion of the network?
active_reachable(X, Y) :- active_adjacent(X, Y).
active_reachable(X, Z) :- active_reachable(X, Y), active_adjacent(Y, Z).

% --- Blast radius ---
% blast_radius(AttackerNode, Count):
%   How many OTHER nodes can the attacker reach from Node
%   using full (pre-failure) topology. Represents the
%   maximum possible lateral movement scope.
blast_radius(N, Count) :-
    component(N),
    Count = #count { M : reachable(N, M), M != N }.

#show blast_radius/2.

% --- Asset reachability from a node ---
% asset_reachable(AttackerNode, Asset):
%   Asset is owned by some component reachable from AttackerNode
%   via the active (non-failed) topology. Used for both
%   compromise exposure and availability checks.
asset_reachable(N, A) :-
    component(N),
    active_reachable(N, M),
    asset(M, A),
    M != N.

% Assets directly owned by the node itself
asset_owned(N, A) :-
    component(N),
    asset(N, A).

% --- Cross-domain links ---
% cross_domain_link(Src, Dst, LinkType):
%   A direct link that crosses a trust zone boundary.
%   These are architectural risk points regardless of
%   which security features are chosen.
cross_domain_link(X, Y, T) :-
    link(X, Y, T),
    node_zone(X, ZX),
    node_zone(Y, ZY),
    ZX != ZY.

% Reverse direction (link can be traversed either way by attacker)
cross_domain_link(Y, X, T) :-
    link(X, Y, T),
    node_zone(X, ZX),
    node_zone(Y, ZY),
    ZX != ZY.

#show cross_domain_link/3.

% --- External entry points ---
% external_entry_point(Node): node is in external_zone.
% These are the highest-priority targets for security hardening.
external_entry_point(N) :-
    component(N),
    node_zone(N, external_zone).

#show external_entry_point/1.

% --- Untrusted nodes ---
untrusted_node(N) :-
    component(N),
    node_zone(N, untrusted_zone).

#show untrusted_node/1.
