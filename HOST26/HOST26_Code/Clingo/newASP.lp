%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Test Case 1
% Last Edited: 6/26/2025
% Purpose: Define a system with three components, three assets
%			and the read/write impacts of each asset
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define components
component(p1; c1; c2).

master(p1).

receiver(c1).
receiver(c2).

bus(bus0).

link(p1,bus0).

link(bus0, c1).

% Define assets
asset(p1, p1r1, read).
asset(p1, p1r1, write).

asset(c1, c1r1, read).
asset(c1, c1r1, write).

%asset(c2, c2r1, read).
asset(c2, c2r1, write).

maintenance_asset(c2r1).

secure_master(m1).


% Define impact of each asset
impact(p1r1, read, 1).
impact(p1r1, write, 5).

impact(c1r1, read, 3).
impact(c1r1, write, 4).

impact(c2r1, read, 3).
impact(c2r1, write, 2).


% Define the allowable latency for each asset read and write - set to 1000 if it does not matter what the latency is
allowable_latency(p1r1, read, 1000).
allowable_latency(p1r1, write, 15).

allowable_latency(c1r1, read, 10).
allowable_latency(c1r1, write, 1000).

allowable_latency(c2r1, read, 1000).
allowable_latency(c2r1, write, 22).


% Symbolic Representation of Policies

% Concatenate Permissions for Policy Generation
%policy_permissions(write,1).
%policy_permissions(read,2).
%policy_permissions(readAndWrite,3).
policy_perm(C,A,readAndWrite) :- asset(C,A,read),  asset(C,A,write).
policy_perm(C,A,read)         :- asset(C,A,read),  not asset(C,A,write).
policy_perm(C,A,write)        :- asset(C,A,write), not asset(C,A,read).


% Define Reachability
reachable(A,B) :- link(A,B). % Direct link
reachable(A,B) :- reachable(A,C), link(C,B), A != B. % Reachable through other components

% Identify what receivers each master can access
accessible_component(M, C) :-
    master(M),
    receiver(C),
    reachable(M, C).

asset_policy(M, C, A, P) :-
    accessible_component(M, C),
    asset(C, A, _),
    policy_perm(C, A, P).

maintenance_policy(M, C, A, P) :-
    secure_master(M),
    asset(C, A, _),
    policy_perm(C, A, P),
    maintenance_asset(A).


#show asset_policy/4.
#show maintenance_policy/4.


%#show accessible_component/2.

