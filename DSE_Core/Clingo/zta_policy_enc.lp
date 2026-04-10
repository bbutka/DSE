%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% zta_policy_enc.lp
%% Purpose: Zero-Trust Architecture policy synthesis.
%% Phase 2 — operates on TOPOLOGY-LEVEL facts only.
%%
%% DESIGN NOTE: Phase 2 is intentionally decoupled from Phase 1 security
%% feature assignments. Phase 1 facts (p1_security, p1_realtime, p1_risk)
%% are injected by the agent but NOT consumed by this encoding. The ZTA
%% policy (firewall placement, trust gaps, least-privilege) is determined
%% by the architecture topology, domain assignments, and access needs —
%% not by which security features were selected. Phase 1 protection levels
%% are consumed by Phase 3 (resilience_enc.lp) where they affect scenario
%% risk amplification via protection_discount.
%%
%% Expects the active integrated instance schema (for example
%% tgt_system_tc9_inst.lp or generated facts).
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

% reachable/2 is pre-computed by ASPGenerator for master->receiver pairs.
% Keeping this relation as static facts avoids grounding a recursive
% transitive closure in Phase 2.

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

% Missing privilege: topology reachable but operation not supported by any asset
missing_privilege(M, C, Op) :-
    access_need(M, C, Op),
    accessible_component(M, C),
    not asset(C, _, Op).

% Count excess grants per master
excess_grant_count(M, N) :-
    master(M),
    N = #count { C, Op : excess_privilege(M, C, Op) }.

% --- policy_tightness: PRECISION metric (pre-firewall) ---
% Measures what fraction of granted access is actually needed.
% 100% = every grant is needed (perfectly tight).
%  50% = half of granted access is excess.
%   0% = nothing granted (or master has no grants).
% Formula: 100 * |needed ∩ reachable| / |granted|
policy_tightness(M, Tightness) :-
    master(M),
    Needed  = #count { C, Op : access_need(M, C, Op), accessible_component(M, C) },
    Granted = #count { C, Op : granted_op(M, C, Op) },
    Granted > 0,
    RawTightness = Needed * 100 / Granted,
    Tightness = #min { RawTightness; 100 }.

% Zero-grant case: undefined precision becomes 100 only when there are
% also no reachable needs; otherwise it is fully unsatisfied (0).
policy_tightness(M, 100) :-
    master(M),
    0 = #count { C, Op : access_need(M, C, Op), accessible_component(M, C) },
    0 = #count { C, Op : granted_op(M, C, Op) }.
policy_tightness(M, 0) :-
    master(M),
    0 < #count { C, Op : access_need(M, C, Op), accessible_component(M, C) },
    0 = #count { C, Op : granted_op(M, C, Op) }.

% Flag: masters with tightness below 50% are over-privileged
over_privileged(M) :- policy_tightness(M, T), T < 50.

% --- Effective grants (post-firewall) ---
% A grant is "blocked by firewall" when the IP sits behind a placed FW
% but the master's path does NOT pass through the FW.
blocked_by_fw(M, C) :-
    master(M), receiver(C),
    place_fw(FW), ip_loc(C, FW),
    not protected(M, C).

% Effective grants: topology-reachable AND either not behind a FW, or
% the master's path passes through the placed FW.
effective_granted_op(M, C, Op) :-
    granted_op(M, C, Op),
    not blocked_by_fw(M, C).
effective_granted_op(M, C, Op) :-
    granted_op(M, C, Op),
    protected(M, C).

% --- effective_policy_tightness: COVERAGE metric (post-firewall, per-mode) ---
% Measures what fraction of needed access is effectively available.
% 100% = all needed access is granted and allowed in this mode.
%  50% = half of needed access is blocked by FW or mode restriction.
%   0% = no needed access available (fully locked down).
% Formula: 100 * |effective_granted ∩ mode_allowed ∩ needed| / |needed|
effective_policy_tightness(M, Mode, Tightness) :-
    master(M), mode(Mode),
    Needed = #count { C, Op : access_need(M, C, Op), accessible_component(M, C) },
    Needed > 0,
    Satisfied = #count { C, Op : access_need(M, C, Op),
                                  effective_granted_op(M, C, Op),
                                  final_allow(M, C, Mode) },
    Tightness = Satisfied * 100 / Needed.

% Zero-output case: no needs declared, or attack_confirmed lockdown.
% Emit 0 so the metric exists for all (master, mode) pairs.
effective_policy_tightness(M, Mode, 0) :-
    master(M), mode(Mode),
    0 = #count { C, Op : access_need(M, C, Op), accessible_component(M, C) }.


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

% Configurable minimum policy server count (default: 1).
% Set system_capability(min_ps_count, N) to require N-way PS redundancy.
min_ps_required(N) :- system_capability(min_ps_count, N).
min_ps_required(1) :- not system_capability(min_ps_count, _).

:- system_capability(min_ps_count, N1),
   system_capability(min_ps_count, N2),
   N1 != N2.

N { place_ps(PS) : cand_ps(PS) } :- min_ps_required(N).

% Hard constraint: insufficient PS candidates must cause UNSAT.
:- min_ps_required(N), N > #count { PS : cand_ps(PS) }.

% Diagnostic (also emitted when the hard constraint fires, for reporting).
insufficient_ps_candidates :- min_ps_required(N),
    N > #count { PS : cand_ps(PS) }.

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

% --- on_path validity diagnostics ---
% Detect stale on_path facts after topology editing.
% Demoted to diagnostics (not hard constraints) so that GUI topology
% edits produce warnings rather than silent UNSAT.
stale_on_path(FW, M, IP) :- on_path(FW, M, IP), not reachable(M, IP).
stale_ip_loc(FW, IP)     :- on_path(FW, _, IP), not ip_loc(IP, FW).

% --- Survivable control plane ---
% Limit how many critical IPs any single PS can govern.
% Prevents a compromised PS from unlocking the entire protected surface.
% Set system_capability(max_critical_ips_per_ps, N) to activate.
ps_critical_ip_count(PS, N) :-
    place_ps(PS),
    N = #count { IP : governs_ip(PS, IP), critical(IP) }.

:- ps_critical_ip_count(PS, N),
   system_capability(max_critical_ips_per_ps, Cap),
   N > Cap.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 6. MODE-AWARE FINE-GRAINED ACCESS CONTROL
%%    Beyond blanket isolation: differentiated by operation,
%%    attestation status, and component criticality.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

mode(normal). mode(attack_suspected). mode(attack_confirmed).

% --- Normal mode ---
% Use explicit allow rules from the integrated instance facts.
final_allow(M, IP, normal) :- allow(M, IP, normal), not deny(M, IP, normal).

% --- attack_suspected mode ---
% Attested masters MAY access non-critical IPs (preserves monitoring).
% Safety-critical IPs denied unconditionally in elevated modes.
% All other (master, IP) pairs denied.
safe_in_suspected(M, C) :- master(M), receiver(C), attested(M),
                            not critical(C), not safety_critical(C).

% Positive grant: attested master accessing non-critical, non-safety IP.
final_allow(M, C, attack_suspected) :- safe_in_suspected(M, C).

% Deny everything else in attack_suspected.
deny(M, C, attack_suspected) :- master(M), receiver(C), not safe_in_suspected(M, C).

% --- attack_confirmed mode ---
% Blanket deny ALL (full isolation, unconditional lockdown).
deny(M, C, attack_confirmed) :- master(M), receiver(C).

% --- Final deny for all modes ---
final_deny(M, IP, S) :- deny(M, IP, S).

% --- Isolation: based on effective allow, not just absence of deny ---
% A low-trust master can effectively reach an IP in mode S only if
% a positive final_allow exists for that pair in that mode.
effective_reachable_low(IP, S) :-
    mode(S), master(M), low_trust_domain(M),
    reachable(M, IP), final_allow(M, IP, S).

isolated(C, S) :- receiver(C), mode(S), not effective_reachable_low(C, S).

% Safety requirement: safety-critical RECEIVERS must be isolated in at least one mode.
% Masters are not subject to isolation (they initiate access, not receive it).
:- safety_critical(C), receiver(C), not isolated(C, _).

% Diagnostic: no attested masters → attack_suspected is fully locked down.
no_attested_masters :- not attested(_).


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
%% 7b. LATERAL MOVEMENT PATH ANALYSIS
%%     Identify attack paths where an attacker enters through an
%%     unguarded non-critical receiver and reaches a critical IP
%%     — either directly (same FW segment) or via multi-hop chains
%%     through other stepping stones sharing bus segments.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% A receiver is an unguarded stepping stone if it is non-critical and
% reachable by at least one master without firewall mediation.
stepping_stone(Hop) :-
    receiver(Hop), not critical(Hop),
    master(M), reachable(M, Hop),
    not protected(M, Hop).

% --- Single-hop lateral path (same FW segment) ---
% A stepping stone and a critical target sit behind the same FW.
% If the stepping stone is compromised, it can attack the target
% from inside the protected perimeter.
lateral_path(M, Hop, Target) :-
    master(M),
    stepping_stone(Hop),
    reachable(M, Hop),
    not protected(M, Hop),
    receiver(Target), critical(Target),
    reachable(M, Target),
    ip_loc(Hop, FW), ip_loc(Target, FW).

% --- Multi-hop lateral reachability ---
% A compromised stepping stone can reach other components on the same
% bus segment.  Two receivers share a segment if they are co-located
% behind the same FW, or if they are both on the same bus without
% any FW between them.
same_segment(A, B) :- ip_loc(A, FW), ip_loc(B, FW), A != B.
same_segment(A, B) :-
    receiver(A), receiver(B), A != B,
    link(Bus, A), link(Bus, B),
    not ip_loc(A, _), not ip_loc(B, _).

% Recursive: lateral reachability through stepping stone chains.
% Depth-bounded by max_lateral_depth (default 3) to keep grounding finite.
max_lateral_depth(D) :- system_capability(max_lateral_depth, D).
max_lateral_depth(3) :- not system_capability(max_lateral_depth, _).

lateral_reach(M, Hop, 1) :-
    master(M), stepping_stone(Hop),
    reachable(M, Hop), not protected(M, Hop).

lateral_reach(M, Next, D+1) :-
    lateral_reach(M, Prev, D),
    stepping_stone(Next),
    same_segment(Prev, Next),
    Next != Prev,
    max_lateral_depth(Max), D < Max.

% Multi-hop lateral path: master can reach a stepping stone chain
% that ends at a component co-located with a critical target.
lateral_path(M, LastHop, Target) :-
    lateral_reach(M, LastHop, _),
    receiver(Target), critical(Target),
    same_segment(LastHop, Target),
    LastHop != Target.

% Count unguarded lateral paths per master (deduplicated)
lateral_path_count(M, N) :-
    master(M),
    N = #count { Hop, Target : lateral_path(M, Hop, Target) }.


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

% Exception mode enforcement: attack_confirmed is unconditional lockdown.
% Exceptions MUST NOT override the blanket deny in this mode.
% Flag any exception that attempts to apply in attack_confirmed mode.
attack_confirmed_exception_violation(M, C, Op, Reason) :-
    policy_exception(M, C, Op, attack_confirmed, Reason).

% Belt-and-suspenders: hard constraint preventing any allow in attack_confirmed.
% (Already implied by the blanket deny on line 214, but this makes it explicit.)
:- final_allow(_, _, attack_confirmed).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 9. COST MINIMISATION / COVERAGE MAXIMISATION
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

resilience_objective_enabled :- phase2_resilience_mode(control_plane).

% --- Max-coverage mode ---
% Maximise the number of firewalled master→IP paths.
% Cost minimisation remains as the tie-break (lower priority).
coverage_objective_enabled :- phase2_coverage_mode(max_coverage).

coverage_count(N) :- N = #count { M, IP : protected(M, IP) }.

#maximize { 1@2, M, IP : coverage_objective_enabled, protected(M, IP) }.

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
#show effective_policy_tightness/3.
#show over_privileged/1.
#show role_excess/3.
#show operational_excess/3.
#show coverage_count/1.

% Control plane
#show ps_critical_ip_count/2.

% Lateral movement
#show lateral_path/3.
#show lateral_path_count/2.

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

% Mode transition triggers (pass-through from instance facts)
#show transition_trigger/3.

% Exceptions
#show unexplained_exception/3.
#show critical_exception/5.
#show attack_confirmed_exception_violation/4.
#show no_attested_masters/0.
#show insufficient_ps_candidates/0.
#show stale_on_path/3.
#show stale_ip_loc/2.
