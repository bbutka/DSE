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
%% 3b. DOMAIN TRUST LEVEL ORDERING
%%     Maps domain names to integer trust levels for ordered comparison.
%%     cross_trust_boundary(DN, DO): true when a compromised node in
%%     domain DN can reach assets belonging to domain DO, and DO has
%%     *strictly higher* trust — i.e. this is a privilege-escalation path.
%%     Same trust level = indirect_exposure_same (1.5×, less severe).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

domain_level(untrusted, 0).
domain_level(low,       0).
domain_level(normal,    1).
domain_level(privileged,2).
domain_level(high,      3).
domain_level(root,      3).

% cross_trust_boundary: compromised is in LOWER trust domain than the asset owner
cross_trust_boundary(DN, DO) :-
    domain_level(DN, LN), domain_level(DO, LO), LN < LO.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. STANDARD EXPOSURE LEVELS  (amplification ×10)
%%    30 = 3.0× direct ownership
%%    20 = 2.0× cross-trust-boundary indirect (privilege escalation path)
%%    15 = 1.5× same-or-higher-trust indirect
%%    10 = 1.0× baseline sentinel
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

direct_exposure(A, N, 30) :-
    compromised(N), asset(N, A, _).

indirect_exposure_cross(A, N, 20) :-
    compromised(N), domain(N, DN),
    asset_reachable(N, A), asset_owner(A, Owner),
    domain(Owner, DO),
    cross_trust_boundary(DN, DO),
    not asset(N, A, _).

indirect_exposure_same(A, N, 15) :-
    compromised(N), domain(N, DN),
    asset_reachable(N, A), asset_owner(A, Owner),
    domain(Owner, DO),
    not cross_trust_boundary(DN, DO),
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
%%
%% Uses p1_risk/3 (asset, action, risk) when available to preserve
%% the CIA action dimension.  Amplification is applied per action;
%% scenario_asset_risk/2 reports the worst-case action for each asset.
%%
%% Falls back to p1_risk/2 (backward compat) when no 3-arg fact exists.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Per-action scenario risk from the 3-arg CIA-aware form
scenario_action_risk(A, Action, ScenRisk) :-
    p1_risk(A, Action, BaseRisk),
    max_amp_factor(A, Factor),
    ScenRisk = BaseRisk * Factor.

% Worst-case action risk per asset (used for total and for backward compat)
scenario_asset_risk(A, ScenRisk) :-
    asset(_, A, _),
    ScenRisk = #max { R : scenario_action_risk(A, _, R) ; 0 : asset(_, A, _) }.

% Fallback: use 2-arg p1_risk when no 3-arg fact exists for this asset
% (i.e. scenario_action_risk never fired for this asset, so max stayed 0
%  and we override with the 2-arg value)
scenario_asset_risk_fallback(A, ScenRisk) :-
    p1_risk(A, BaseRisk),
    not p1_risk(A, _, _),
    max_amp_factor(A, Factor),
    ScenRisk = BaseRisk * Factor.

% Merge: if fallback exists and scenario_asset_risk is 0 (no 3-arg facts)
scenario_asset_risk(A, ScenRisk) :-
    scenario_asset_risk_fallback(A, ScenRisk),
    scenario_asset_risk(A, 0).

scenario_total_risk(Total) :-
    Total = #sum { R, A : scenario_asset_risk(A, R) }.


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


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 10. FUNCTIONAL RESILIENCE — MISSION CAPABILITY ASSESSMENT
%%     Determines which mission capabilities survive each scenario.
%%     A capability is LOST if any of its dependencies are broken:
%%       - A required service drops below quorum
%%       - A required component is failed, compromised, or cut off
%%       - A required access path is broken (component unreachable)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% A required service is broken if it drops below quorum
% (both unavailable and degraded represent quorum loss)
capability_service_broken(Cap, Svc) :-
    capability_requires_service(Cap, Svc),
    service_unavailable(Svc).

capability_service_broken(Cap, Svc) :-
    capability_requires_service(Cap, Svc),
    service_degraded(Svc).

% A required component is broken if failed, compromised, or cut off
capability_component_broken(Cap, C) :-
    capability_requires_component(Cap, C),
    failed(C).

capability_component_broken(Cap, C) :-
    capability_requires_component(Cap, C),
    compromised(C).

capability_component_broken(Cap, C) :-
    capability_requires_component(Cap, C),
    node_cut_off(C).

% A required access path is broken if the target component is
% failed, compromised, cut off, OR unreachable from the master
capability_access_broken(Cap, M, C, Op) :-
    capability_requires_access(Cap, M, C, Op),
    failed(C).

capability_access_broken(Cap, M, C, Op) :-
    capability_requires_access(Cap, M, C, Op),
    failed(M).

capability_access_broken(Cap, M, C, Op) :-
    capability_requires_access(Cap, M, C, Op),
    compromised(C).

capability_access_broken(Cap, M, C, Op) :-
    capability_requires_access(Cap, M, C, Op),
    not active_reachable(M, C),
    M != C.

% A capability is LOST if any hard dependency is broken
capability_lost(Cap) :-
    capability(Cap),
    capability_service_broken(Cap, _).

capability_lost(Cap) :-
    capability(Cap),
    capability_component_broken(Cap, _).

capability_lost(Cap) :-
    capability(Cap),
    capability_access_broken(Cap, _, _, _).

% A capability is OK if not lost and not degraded
capability_ok(Cap) :-
    capability(Cap),
    not capability_lost(Cap),
    not capability_degraded(Cap).

% Count capabilities by status
capability_ok_count(N) :-
    N = #count { Cap : capability_ok(Cap) }.

capability_degraded_count(N) :-
    N = #count { Cap : capability_degraded(Cap) }.

capability_lost_count(N) :-
    N = #count { Cap : capability_lost(Cap) }.

% Essential capabilities lost — system is non-functional
essential_capability_lost(Cap) :-
    capability_lost(Cap),
    capability_criticality(Cap, essential).

% System functional status
system_functional :-
    not essential_capability_lost(_).

system_degraded :-
    system_functional,
    capability_lost(_).

system_degraded :-
    system_functional,
    capability_degraded(_).

system_non_functional :-
    essential_capability_lost(_).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 11. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show blast_radius/2.
#show max_amp_factor/2.
#show scenario_action_risk/3.
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
#show active_ps_count/1.
#show ungovernerd_pep/1.
#show stale_policy_active/0.
#show control_plane_degraded/0.
#show control_plane_compromised/0.
#show pep_bypassed/1.
#show ps_compromised/1.
#show direct_exposure/3.
#show indirect_exposure_cross/3.
#show unmediated_exposure/3.
#show stale_policy_exposure/2.
#show capability_ok/1.
#show capability_degraded/1.
#show capability_lost/1.
#show capability_service_broken/2.
#show capability_component_broken/2.
#show capability_access_broken/4.
#show essential_capability_lost/1.
#show system_functional/0.
#show system_degraded/0.
#show system_non_functional/0.
#show capability_ok_count/1.
#show capability_degraded_count/1.
#show capability_lost_count/1.
