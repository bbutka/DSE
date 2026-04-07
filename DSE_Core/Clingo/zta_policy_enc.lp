%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% zta_policy_enc.lp
%% Purpose: Zero-Trust Architecture policy synthesis.
%% Phase 2 — expects Phase 1 injected facts and the active integrated
%% instance schema (for example tgt_system_tc9_inst.lp or generated facts).
%%
%% Sections:
%%  1. Reachability and ACL synthesis
%%  2. Least-privilege analysis
%%  3. Role-based access (RBAC)
%%  4. Mission-context-aware access
%%  5. Firewall and policy-server placement
%%  6. Mode-aware fine-grained access control
%%  7. Trust anchor / attestation gaps
%%  8. Policy exceptions
%%  9. Cost minimisation
%% 10. Output
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 0. GRADUATED DOMAIN HELPERS
%%    Classifies domain levels into trust tiers for use throughout
%%    this encoding.  Replaces binary low/high checks so that the
%%    six-level domain model (untrusted/low/normal/privileged/high/root)
%%    is handled consistently.
%%
%%    low_trust_domain(N)  — untrusted, low, or normal: must be firewalled
%%                           before accessing critical IPs.
%%    high_trust_domain(N) — privileged, high, or root: qualifies for
%%                           key-storage and attestation gap checks.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

low_trust_domain(N) :- domain(N, untrusted).
low_trust_domain(N) :- domain(N, low).
low_trust_domain(N) :- domain(N, normal).

high_trust_domain(N) :- domain(N, privileged).
high_trust_domain(N) :- domain(N, high).
high_trust_domain(N) :- domain(N, root).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1. REACHABILITY AND ACL SYNTHESIS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

reachable(X, Y) :- link(X, Y).
reachable(X, Y) :- reachable(X, Z), link(Z, Y).

accessible_component(M, C) :-
    master(M), receiver(C), reachable(M, C).

% Derive the permission level granted to each (component, asset) pair
policy_perm(C, A, readAndWrite) :- asset(C, A, read),  asset(C, A, write).
policy_perm(C, A, read)         :- asset(C, A, read),  not asset(C, A, write).
policy_perm(C, A, write)        :- asset(C, A, write), not asset(C, A, read).

% Expand policy_perm to individual operations
policy_perm_op(C, A, read)  :- policy_perm(C, A, readAndWrite).
policy_perm_op(C, A, write) :- policy_perm(C, A, readAndWrite).
policy_perm_op(C, A, read)  :- policy_perm(C, A, read).
policy_perm_op(C, A, write) :- policy_perm(C, A, write).

% Full ACL: master → component → asset → permission (topology-derived, normal mode)
asset_policy(M, C, A, P) :-
    accessible_component(M, C),
    asset(C, A, _),
    policy_perm(C, A, P).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 2. LEAST-PRIVILEGE ANALYSIS
%%    Compare granted access against declared access_need/3.
%%    access_need(Master, Component, Op) = minimum required.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% A master has granted access to a component/operation via topology
granted_op(M, C, Op) :-
    accessible_component(M, C),
    policy_perm_op(C, A, Op).

% Excess privilege: granted but not needed
excess_privilege(M, C, Op) :-
    granted_op(M, C, Op),
    not access_need(M, C, Op).

% Missing privilege: needed but no topological path exists
missing_privilege(M, C, Op) :-
    access_need(M, C, Op),
    not accessible_component(M, C).

% Count excess grants per master
excess_grant_count(M, N) :-
    master(M),
    N = #count { C, Op : excess_privilege(M, C, Op) }.

% Policy tightness score: 0 = fully excess, 100 = perfectly tight
% tightness = 100 * needed / granted
policy_tightness(M, Tightness) :-
    master(M),
    Needed  = #count { C, Op : access_need(M, C, Op), accessible_component(M, C) },
    Granted = #count { C, Op : granted_op(M, C, Op) },
    Granted > 0,
    Tightness = Needed * 100 / Granted.

% Flag: masters with tightness below 50% are over-privileged
over_privileged(M) :- policy_tightness(M, T), T < 50.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 3. ROLE-BASED ACCESS CONTROL (RBAC)
%%    Roles add a second permission layer beyond topology.
%%    role_need(Role, Component, Op) = what the role permits.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Role permission check: role authorises access
role_authorised(M, C, Op) :-
    role(M, R),
    role_need(R, C, Op).

% Access that is topologically reachable but role does not authorise
role_excess(M, C, Op) :-
    granted_op(M, C, Op),
    not role_authorised(M, C, Op).

% Role-tightened policy: only allow where BOTH topology AND role agree
role_allow(M, C, A, Op) :-
    accessible_component(M, C),
    asset(C, A, _),
    role_authorised(M, C, Op),
    policy_perm_op(C, A, Op).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. MISSION-CONTEXT ACCESS
%%    mission_access(M, C, Op, Phase) from the integrated instance facts
%%    gives phase-conditional access ground truth.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Operational excess: granted topologically but not in any mission phase
operational_excess(M, C, Op) :-
    granted_op(M, C, Op),
    not mission_access(M, C, Op, operational),
    not mission_access(M, C, Op, maintenance),
    not mission_access(M, C, Op, emergency).

% Mission-context-aware final access decision per phase
mission_final_allow(M, C, Op, Phase) :-
    accessible_component(M, C),
    mission_access(M, C, Op, Phase).

mission_final_deny(M, C, Op, Phase) :-
    granted_op(M, C, Op),
    mission_phase(Phase),
    not mission_access(M, C, Op, Phase).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 5. FIREWALL AND POLICY-SERVER PLACEMENT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

{ place_fw(FWL) : cand_fw(FWL) }.
1 { place_ps(PS) : cand_ps(PS) } N :- N = #count { PS : cand_ps(PS) }.

protected(M, IP) :- place_fw(FWL), on_path(FWL, M, IP).

% Integrity constraint: low/normal/untrusted masters must be firewalled before critical IPs
:- master(M), low_trust_domain(M), critical(IP),
   reachable(M, IP), not protected(M, IP).

governs_ip(PS, IP) :-
    place_ps(PS),
    place_fw(FWL),
    ip_loc(IP, FWL),
    governs(PS, FWL).

:- place_fw(FWL), ip_loc(IP, FWL), not governs_ip(_, IP).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 6. MODE-AWARE FINE-GRAINED ACCESS CONTROL
%%    Beyond blanket isolation: differentiated by operation,
%%    attestation status, and component criticality.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

mode(normal). mode(attack_suspected). mode(attack_confirmed).

% Normal mode: use explicit allow rules from the integrated instance facts
final_allow(M, IP, normal) :- allow(M, IP, normal), not deny(M, IP, normal).

% attack_suspected: attested masters MAY still access non-critical IPs
%  → preserves monitoring capability even under elevated threat
% Auxiliary: safe = attested master accessing a non-critical IP
safe_in_suspected(M, C) :- master(M), receiver(C), attested(M), not critical(C).
deny(M, C, attack_suspected) :- master(M), receiver(C), not safe_in_suspected(M, C).

% attack_confirmed: blanket deny ALL (full isolation)
deny(M, C, attack_confirmed) :- master(M), receiver(C).

% Safety-critical components: isolated in BOTH elevated modes
deny(M, C, attack_suspected) :- master(M), safety_critical(C).

% Can a low/normal/untrusted master still reach an IP in mode S?
reachable_low(IP, S) :-
    mode(S), master(M), low_trust_domain(M),
    reachable(M, IP), not deny(M, IP, S).

isolated(C, S) :- receiver(C), mode(S), not reachable_low(C, S).

% Safety requirement: safety-critical RECEIVERS must be isolated in at least one mode.
% Masters are not subject to isolation (they initiate access, not receive it).
:- safety_critical(C), receiver(C), not isolated(C, _).

% Final access decisions
final_allow(M, IP, S) :- allow(M, IP, S), not deny(M, IP, S), mode(S), S != normal.
final_deny(M, IP, S)  :- deny(M, IP, S).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 7. TRUST ANCHOR / ATTESTATION GAPS
%%    Identify components and masters that lack trust anchors.
%%    These are findings, not hard constraints.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Gap: IP lacks hardware root of trust
trust_gap_rot(C)  :- receiver(C), not hardware_rot(C).

% Gap: IP lacks secure boot
trust_gap_sboot(C) :- receiver(C), not secure_boot(C).

% Gap: master lacks platform attestation
trust_gap_attest(M) :- master(M), not attested(M).

% Gap: a master accessing a privileged/high/root IP is itself unattested
unattested_privileged_access(M, C) :-
    accessible_component(M, C),
    high_trust_domain(C),
    trust_gap_attest(M).

% Gap: policy server without signed policy enforcement
unsigned_ps(PS) :- policy_server(PS), not signed_policy(PS).

% Gap: key storage absent from privileged/high/root component
trust_gap_keys(C) :-
    receiver(C), high_trust_domain(C),
    not key_storage(C).

% Trust score per component: count how many anchors are present (max 3)
trust_anchor_count(C, N) :-
    receiver(C),
    N = #count { hw_rot  : hardware_rot(C)  ;
                 sboot   : secure_boot(C)   ;
                 keystore: key_storage(C)   }.

% Component trust level
trust_level(C, high)   :- trust_anchor_count(C, 3).
trust_level(C, medium) :- trust_anchor_count(C, N), N >= 1, N < 3.
trust_level(C, low)    :- trust_anchor_count(C, 0).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 8. POLICY EXCEPTIONS
%%    policy_exception/5 from the integrated instance facts documents
%%    granted exceptions.  Verify they have justification.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% An exception exists without a declared need: potential policy drift
unexplained_exception(M, C, Op) :-
    policy_exception(M, C, Op, _, _),
    not access_need(M, C, Op).

% Exception grants access to a critical IP: elevated finding
critical_exception(M, C, Op, Ph, Reason) :-
    policy_exception(M, C, Op, Ph, Reason),
    critical(C).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 9. COST MINIMISATION
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

resilience_objective_enabled :- phase2_resilience_mode(control_plane).

safety_fw_penalty_weight(W) :-
    phase2_safety_fw_penalty_weight(W).
safety_fw_penalty_weight(250) :-
    resilience_objective_enabled,
    not phase2_safety_fw_penalty_weight(_).

concentration_penalty_weight(W) :-
    phase2_concentration_penalty_weight(W).
concentration_penalty_weight(400) :-
    resilience_objective_enabled,
    not phase2_concentration_penalty_weight(_).

safety_guarded_fw(FW) :-
    cand_fw(FW),
    pep_guards(FW, IP),
    safety_critical(IP).

critical_guarded_fw(FW) :-
    cand_fw(FW),
    pep_guards(FW, IP),
    critical(IP).

perimeter_guarded_fw(FW) :-
    critical_guarded_fw(FW),
    not safety_guarded_fw(FW).

mixed_ps_concentration_pair(PS, FWs, FWp) :-
    resilience_objective_enabled,
    place_ps(PS),
    place_fw(FWs),
    place_fw(FWp),
    safety_guarded_fw(FWs),
    perimeter_guarded_fw(FWp),
    governs(PS, FWs),
    governs(PS, FWp).

unplaced_safety_fw_penalty(Total) :-
    resilience_objective_enabled,
    safety_fw_penalty_weight(W),
    Total = #sum { W, FW : safety_guarded_fw(FW), not place_fw(FW) }.

control_plane_concentration_penalty(Total) :-
    resilience_objective_enabled,
    concentration_penalty_weight(W),
    Total = #sum { W, PS, FWs, FWp : mixed_ps_concentration_pair(PS, FWs, FWp) }.

total_zta_cost(C) :-
    C = #sum { Cost,   FW : place_fw(FW),  fw_cost(FW,   Cost)  ;
               CostPS, PS : place_ps(PS),  ps_cost(PS, CostPS) }.

#minimize { C : total_zta_cost(C) }.
#minimize { W, FW : resilience_objective_enabled,
                     safety_guarded_fw(FW),
                     not place_fw(FW),
                     safety_fw_penalty_weight(W) }.
#minimize { W, PS, FWs, FWp : resilience_objective_enabled,
                                mixed_ps_concentration_pair(PS, FWs, FWp),
                                concentration_penalty_weight(W) }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 10. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show place_fw/1.
#show place_ps/1.
#show final_allow/3.
#show final_deny/3.
#show total_zta_cost/1.
#show unplaced_safety_fw_penalty/1.
#show control_plane_concentration_penalty/1.
#show asset_policy/4.
#show role_allow/4.
#show isolated/2.
#show protected/2.
#show governs_ip/2.

% Least-privilege findings
#show excess_privilege/3.
#show missing_privilege/3.
#show excess_grant_count/2.
#show policy_tightness/2.
#show over_privileged/1.
#show role_excess/3.
#show operational_excess/3.

% Trust findings
#show trust_gap_rot/1.
#show trust_gap_sboot/1.
#show trust_gap_attest/1.
#show unattested_privileged_access/2.
#show unsigned_ps/1.
#show trust_gap_keys/1.
#show trust_level/2.

% Mission context
#show mission_final_allow/4.
#show mission_final_deny/4.

% Exceptions
#show unexplained_exception/3.
#show critical_exception/5.
