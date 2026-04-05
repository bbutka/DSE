%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% resilience_tc9_enc.lp
%% Purpose: Resilience and compromise scenario analysis.
%%          Adapted for HOST26 asset/3 schema.
%%
%% Expects from runner (injected as named program "scenario"):
%%   p1_risk(AssetReg, MaxRisk)  — base risk per asset from Phase 1
%%   compromised(Node)           — scenario: node compromised
%%   failed(Node)                — scenario: node has failed
%%
%% Expects from testCase9_inst.lp:
%%   component/1, link/2, domain/2, asset/3, receiver/1,
%%   service_component/2, service_quorum/2,
%%   policy_server/1, policy_enforcement_point/1,
%%   pep_guards/2, ps_governs_pep/2, governs/2,
%%   attested/1, signed_policy/1, hardware_rot/1
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1. TOPOLOGY — bidirectional adjacency, failure-aware
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

adjacent(X, Y) :- link(X, Y).
adjacent(X, Y) :- link(Y, X).

active_adjacent(X, Y) :- adjacent(X, Y), not failed(X), not failed(Y).

reachable(X, Y) :- adjacent(X, Y).
reachable(X, Z) :- reachable(X, Y), adjacent(Y, Z).

active_reachable(X, Y) :- active_adjacent(X, Y).
active_reachable(X, Z) :- active_reachable(X, Y), active_adjacent(Y, Z).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 2. BLAST RADIUS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

blast_radius(N, Count) :-
    component(N),
    Count = #count { M : reachable(N, M), M != N }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 3. ASSET OWNERSHIP AND REACHABILITY
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

asset_owner(A, C) :- asset(C, A, _).

asset_reachable(N, A) :- asset(N, A, _).
asset_reachable(N, A) :- reachable(N, C), asset(C, A, _), C != N.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. STANDARD EXPOSURE LEVELS  (amplification ×10)
%%    30 = 3.0× direct ownership
%%    20 = 2.0× cross-domain indirect
%%    15 = 1.5× same-domain indirect
%%    10 = 1.0× baseline sentinel
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

direct_exposure(A, N, 30) :-
    compromised(N), asset(N, A, _).

indirect_exposure_cross(A, N, 20) :-
    compromised(N), domain(N, DN),
    asset_reachable(N, A), asset_owner(A, Owner),
    domain(Owner, DO), DN != DO,
    not asset(N, A, _).

indirect_exposure_same(A, N, 15) :-
    compromised(N), domain(N, DN),
    asset_reachable(N, A), asset_owner(A, Owner),
    domain(Owner, DO), DN = DO,
    not asset(N, A, _).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 5. CONTROL PLANE COMPROMISE
%%    PS compromise → governed PEPs untrusted → bypass
%%    PEP bypass → unmediated master→IP access
%%    PS failure  → stale policy (slight risk elevation)
%%    PS conflict → inconsistent deny/allow (slight elevation)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% If Phase 2 placement is provided by the runner, only deployed PEPs/PSes
% participate in the resilience model. Otherwise fall back to the testcase
% topology facts so the encoding still works standalone.
phase2_context_present :- deployed_pep(_).
phase2_context_present :- deployed_ps(_).

active_policy_server(PS) :- deployed_ps(PS).
active_policy_server(PS) :- policy_server(PS), not phase2_context_present.

active_policy_enforcement_point(FWL) :- deployed_pep(FWL).
active_policy_enforcement_point(FWL) :- policy_enforcement_point(FWL), not phase2_context_present.

active_pep_guards(FWL, C) :-
    active_policy_enforcement_point(FWL),
    pep_guards(FWL, C).

active_ps_governs_pep(PS, FWL) :-
    active_policy_server(PS),
    active_policy_enforcement_point(FWL),
    ps_governs_pep(PS, FWL).

% Policy server compromised
ps_compromised(PS) :- compromised(PS), active_policy_server(PS).

% PEP is bypassed if its governing PS is compromised,
% or if the PEP itself is directly compromised/failed
pep_bypassed(FWL) :- compromised(FWL), active_policy_enforcement_point(FWL).
pep_bypassed(FWL) :- ps_compromised(PS), active_ps_governs_pep(PS, FWL).

% When PEP is bypassed, all masters gain unmediated access to IPs behind it
% (factor 25 = 2.5× — between cross-domain indirect and direct)
unmediated_exposure(A, M, 25) :-
    master(M), pep_bypassed(PEP),
    active_pep_guards(PEP, C), asset(C, A, _),
    not compromised(M),
    not failed(C), not failed(M).

% PS failure → stale policy (factor 12 = 1.2×)
stale_policy_exposure(A, 12) :-
    failed(PS), active_policy_server(PS),
    active_ps_governs_pep(PS, FWL), not failed(FWL),
    active_pep_guards(FWL, C), asset(C, A, _),
    not pep_bypassed(FWL).

% Only ps1 remains but ps0 (which has signed policy) is down
% → unsigned-only policy risk (factor 11 = 1.1×)
unsigned_only_exposure(A, 11) :-
    active_policy_server(ps1),
    failed(ps0), not failed(ps1),
    not unsigned_ps(ps1),  % ps1 is also unsigned → same risk
    active_pep_guards(_, C), asset(C, A, _).

unsigned_only_exposure(A, 11) :-
    active_policy_server(ps1),
    failed(ps0), not failed(ps1),
    unsigned_ps(ps1),
    active_pep_guards(_, C), asset(C, A, _).

% PS conflict: both PSes up, but ps0 is compromised → conflicting decisions
% Model as slightly elevated indirect exposure (factor 13 = 1.3×)
ps_conflict_exposure(A, 13) :-
    active_policy_server(ps1),
    ps_compromised(ps0), not failed(ps1),
    active_pep_guards(_, C), asset(C, A, _).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 6. MAXIMUM AMPLIFICATION
%%    Combines standard and control-plane exposures.
%%    Sentinel 10 ensures #max never evaluates over empty set.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

max_amp_factor(A, Factor) :-
    asset(_, A, _),
    Factor = #max {
        F    : direct_exposure(A, _, F)          ;
        F    : indirect_exposure_cross(A, _, F)  ;
        F    : indirect_exposure_same(A, _, F)   ;
        F    : unmediated_exposure(A, _, F)       ;
        F    : stale_policy_exposure(A, F)        ;
        F    : unsigned_only_exposure(A, F)       ;
        F    : ps_conflict_exposure(A, F)         ;
        10   : asset(_, A, _)                     % baseline sentinel
    }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 7. SCENARIO RISK
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

scenario_asset_risk(A, ScenRisk) :-
    p1_risk(A, BaseRisk),
    max_amp_factor(A, Factor),
    ScenRisk = BaseRisk * Factor.

scenario_total_risk(Total) :-
    Total = #sum { R, A : scenario_asset_risk(A, R) }.

blast_radius_penalty(Penalty) :-
    Penalty = #max { Value, N : compromised(N), blast_radius(N, B), Value = B * 10 ; 0 }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 8. SERVICE HEALTH
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

asset_available(A)   :- asset(Owner, A, _), not failed(Owner).
asset_unavailable(A) :- asset(Owner, A, _), failed(Owner).

% A receiver node is cut off if no master can active_reach it
node_cut_off(C) :-
    receiver(C), not failed(C),
    not active_reachable(_, C).

% Service health: count live members and compare to quorum
service_live_count(S, N) :-
    service_quorum(S, _),
    N = #count { C : service_component(S, C),
                     not failed(C),
                     not node_cut_off(C) }.

service_ok(S) :-
    service_quorum(S, Q),
    service_live_count(S, N), N >= Q.

service_degraded(S) :-
    service_quorum(S, Q),
    service_live_count(S, N),
    N > 0, N < Q.

service_unavailable(S) :-
    service_quorum(S, _),
    service_live_count(S, 0).

% A component is cut off from ALL assets if its bus is failed
component_bus_cut(C) :-
    receiver(C), not failed(C),
    node_cut_off(C).

availability_penalty(Penalty) :-
    Cut = #count { C : node_cut_off(C) },
    Unavailable = #count { A : asset_unavailable(A) },
    Penalty = Cut * 20 + Unavailable * 10.

service_penalty(Penalty) :-
    Degraded = #count { S : service_degraded(S) },
    Unavailable = #count { S : service_unavailable(S) },
    Penalty = Degraded * 50 + Unavailable * 100.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 9. CONTROL PLANE HEALTH
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% How many policy servers remain operational
active_ps_count(N) :-
    N = #count { PS : active_policy_server(PS), not failed(PS), not compromised(PS) }.

% A PEP has a healthy governor if some governing PS is alive and not compromised
has_healthy_governor(FWL) :-
    active_ps_governs_pep(PS, FWL),
    not failed(PS),
    not ps_compromised(PS).

% Any PEP currently lacking a healthy governing PS
ungovernerd_pep(FWL) :-
    active_policy_enforcement_point(FWL),
    not failed(FWL),
    not has_healthy_governor(FWL).

% Stale policy: any PS failure leaves surviving PEPs with un-refreshed policy
stale_policy_active :- stale_policy_exposure(_, _).

% Control plane is degraded if any PEP is ungoverned, bypassed, or serving stale policy
control_plane_degraded :-
    ungovernerd_pep(_).
control_plane_degraded :-
    pep_bypassed(_).
control_plane_degraded :-
    stale_policy_active.

control_plane_compromised :-
    ps_compromised(_).

control_plane_penalty(Penalty) :-
    Bypassed = #count { FWL : pep_bypassed(FWL) },
    CompromisedPS = #count { PS : ps_compromised(PS) },
    Degraded = #count { X : control_plane_degraded, X = 1 },
    Stale = #count { X : stale_policy_active, X = 1 },
    Compromised = #count { X : control_plane_compromised, X = 1 },
    Penalty = Bypassed * 30 + CompromisedPS * 40 + Degraded * 50 + Stale * 20 + Compromised * 100.

scenario_resilience_score(Score) :-
    scenario_total_risk(Total),
    blast_radius_penalty(Blast),
    availability_penalty(Avail),
    service_penalty(Service),
    control_plane_penalty(ControlPlane),
    Score = Total + Blast + Avail + Service + ControlPlane.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 10. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show blast_radius/2.
#show max_amp_factor/2.
#show scenario_asset_risk/2.
#show scenario_total_risk/1.
#show asset_available/1.
#show asset_unavailable/1.
#show node_cut_off/1.
#show service_ok/1.
#show service_degraded/1.
#show service_unavailable/1.
#show service_live_count/2.
#show component_bus_cut/1.
#show blast_radius_penalty/1.
#show availability_penalty/1.
#show service_penalty/1.
#show active_ps_count/1.
#show ungovernerd_pep/1.
#show stale_policy_active/0.
#show control_plane_degraded/0.
#show control_plane_compromised/0.
#show control_plane_penalty/1.
#show scenario_resilience_score/1.
#show pep_bypassed/1.
#show ps_compromised/1.
#show direct_exposure/3.
#show indirect_exposure_cross/3.
#show unmediated_exposure/3.
#show stale_policy_exposure/2.
