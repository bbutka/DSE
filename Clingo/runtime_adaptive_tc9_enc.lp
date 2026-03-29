%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% runtime_adaptive_tc9_enc.lp
%% Purpose: Minimal closed-loop runtime extension for tc9.
%%
%% Expects:
%%   - testCase9_inst.lp
%%   - runtime_monitor_tc9_inst.lp
%%   - injected Phase 1 facts: p1_logging/2
%%   - injected Phase 2 facts: deployed_pep/1, deployed_ps/1
%%   - injected observations: observed(Node, SignalKind, Severity)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 0. GRADUATED DOMAIN HELPERS  (mirrors zta_policy_enc.lp)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

high_trust_domain(N) :- domain(N, privileged).
high_trust_domain(N) :- domain(N, high).
high_trust_domain(N) :- domain(N, root).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1. TOPOLOGY / CONTEXT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

reachable(X, Y) :- link(X, Y).
reachable(X, Y) :- reachable(X, Z), link(Z, Y).

accessible_component(M, C) :-
    master(M), receiver(C), reachable(M, C).

phase2_context_present :- deployed_pep(_).
phase2_context_present :- deployed_ps(_).

active_policy_server(PS) :-
    deployed_ps(PS).
active_policy_server(PS) :-
    policy_server(PS),
    not phase2_context_present.

active_policy_enforcement_point(PEP) :-
    deployed_pep(PEP).
active_policy_enforcement_point(PEP) :-
    policy_enforcement_point(PEP),
    not phase2_context_present.

observed_node(N) :- master(N).
observed_node(N) :- receiver(N).
observed_node(N) :- active_policy_server(N).
observed_node(N) :- active_policy_enforcement_point(N).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 2. MONITOR PLACEMENT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

monitor_context_present :- deployed_monitor(_).

{ place_monitor(M) : cand_monitor(M) } :-
    not monitor_context_present.

active_monitor(M) :- deployed_monitor(M).
active_monitor(M) :- place_monitor(M), not monitor_context_present.

covered(N) :-
    active_monitor(M),
    monitor_covers(M, N).

% Safety-critical and active control-plane coverage must be present.
:- safety_critical(C), not covered(C).
:- active_policy_server(PS), not covered(PS).
:- active_policy_enforcement_point(PEP), not covered(PEP).

monitor_total_cost(Cost) :-
    Cost = #sum { C, M : active_monitor(M), monitor_cost(M, C) }.

:- monitor_total_cost(Cost),
   system_capability(max_monitor_cost, MaxCost),
   Cost > MaxCost.

#maximize { W@2, N : covered(N), monitor_priority(N, W) }.
#minimize { C@1, M : active_monitor(M), monitor_cost(M, C) }.

monitor_visibility(N, Score) :-
    observed_node(N),
    Score = #max { S, M : active_monitor(M), monitor_covers(M, N), monitor_strength(M, S);
                   0    : observed_node(N) }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 3. OBSERVABILITY / EVIDENCE
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

logging_visibility(C, 0)  :- p1_logging(C, no_logging).
logging_visibility(C, 6)  :- p1_logging(C, some_logging).
logging_visibility(C, 15) :- p1_logging(C, zero_trust_logger).
% Non-receivers (masters, PSes, PEPs) have no logging feature — always 0.
logging_visibility(N, 0)  :- observed_node(N), not receiver(N).
% Safety fallback: receivers for which no p1_logging fact was injected
% (e.g. Phase 1 was skipped or partial) default to 0 rather than being
% undefined, which would silently drop their observability_score and
% cause all signals from them to be missed.
logging_visibility(C, 0)  :- receiver(C), not p1_logging(C, _).

observability_score(N, Score) :-
    observed_node(N),
    monitor_visibility(N, Mon),
    logging_visibility(N, Log),
    Score = Mon + Log.

observable(N) :-
    observability_score(N, Score),
    Score > 0.

missed_signal(N, Signal) :-
    observed(N, Signal, _),
    not observable(N).

alert_score(N, Score) :-
    observed_node(N),
    Score = #sum { Value, Signal :
        observed(N, Signal, Sev),
        observable(N),
        signal_weight(Signal, W),
        Value = Sev * W }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. STATIC TRUST PRIOR
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

base_penalty(N, 25) :-
    master(N),
    not attested(N).

base_penalty(N, 15) :-
    active_policy_server(N),
    not signed_policy(N).

base_penalty(N, 10) :-
    receiver(N),
    not hardware_rot(N).

base_penalty(N, 5) :-
    receiver(N),
    not secure_boot(N).

base_penalty(N, 5) :-
    receiver(N),
    high_trust_domain(N),
    not key_storage(N).

base_score(N, Score) :-
    observed_node(N),
    Score = #sum { P : base_penalty(N, P) }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 5. ANOMALY SCORE / TRUST UPDATE
%%
%% anomaly_score = base_score + alert_score only.
%% observability_score is a separate confidence metric and must
%% NOT be added here: adding it would penalise well-monitored
%% nodes and create a perverse incentive against strong coverage.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

anomaly_score(N, Total) :-
    observed_node(N),
    base_score(N, Base),
    alert_score(N, Alerts),
    Total = Base + Alerts.

trust_state(N, compromised) :-
    anomaly_score(N, Score),
    Score >= 100.

trust_state(N, low) :-
    anomaly_score(N, Score),
    Score >= 70,
    Score < 100.

trust_state(N, medium) :-
    anomaly_score(N, Score),
    Score >= 40,
    Score < 70.

trust_state(N, high) :-
    anomaly_score(N, Score),
    Score < 40.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 6. AUTOMATIC MODE TRANSITION
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

current_mode(attack_confirmed) :-
    trust_state(_, compromised).

current_mode(attack_confirmed) :-
    safety_critical(N),
    trust_state(N, low).

current_mode(attack_confirmed) :-
    active_policy_server(N),
    trust_state(N, low).

current_mode(attack_suspected) :-
    not current_mode(attack_confirmed),
    trust_state(_, low).

current_mode(attack_suspected) :-
    not current_mode(attack_confirmed),
    trust_state(_, medium).

current_mode(normal) :-
    not current_mode(attack_confirmed),
    not current_mode(attack_suspected).

mode_trigger(N, attack_confirmed) :-
    current_mode(attack_confirmed),
    trust_state(N, compromised).

mode_trigger(N, attack_confirmed) :-
    current_mode(attack_confirmed),
    safety_critical(N),
    trust_state(N, low).

mode_trigger(N, attack_suspected) :-
    current_mode(attack_suspected),
    trust_state(N, low).

mode_trigger(N, attack_suspected) :-
    current_mode(attack_suspected),
    trust_state(N, medium).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 7. ADAPTIVE RESPONSE
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

response_action(quarantine, N) :-
    trust_state(N, compromised).

response_action(quarantine, N) :-
    safety_critical(N),
    trust_state(N, low).

response_action(re_attest, M) :-
    master(M),
    trust_state(M, medium).

% re_attest is suppressed when quarantine is already triggered:
% a quarantined node cannot execute attestation.
response_action(re_attest, M) :-
    master(M),
    trust_state(M, low),
    not response_action(quarantine, M).

response_action(re_attest, M) :-
    master(M),
    trust_state(M, compromised),
    not response_action(quarantine, M).

response_action(lockdown_pep, PEP) :-
    active_policy_enforcement_point(PEP),
    current_mode(attack_confirmed).

response_action(force_signed_policy, PS) :-
    active_policy_server(PS),
    current_mode(attack_suspected),
    not signed_policy(PS).

adaptive_deny(M, C, attack_suspected) :-
    current_mode(attack_suspected),
    accessible_component(M, C),
    critical(C),
    trust_state(M, medium).

adaptive_deny(M, C, attack_suspected) :-
    current_mode(attack_suspected),
    accessible_component(M, C),
    critical(C),
    trust_state(M, low).

adaptive_deny(M, C, attack_suspected) :-
    current_mode(attack_suspected),
    accessible_component(M, C),
    critical(C),
    trust_state(M, compromised).

adaptive_deny(M, C, attack_suspected) :-
    current_mode(attack_suspected),
    accessible_component(M, C),
    not attested(M),
    critical(C).

adaptive_deny(M, C, attack_suspected) :-
    current_mode(attack_suspected),
    accessible_component(M, C),
    response_action(quarantine, C).

adaptive_deny(M, C, attack_confirmed) :-
    current_mode(attack_confirmed),
    accessible_component(M, C).

adaptive_allow(M, C, Mode) :-
    current_mode(Mode),
    accessible_component(M, C),
    not adaptive_deny(M, C, Mode).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 8. ENFORCEMENT BRIDGE
%%
%% Bridges the runtime adaptive layer with Phase 2 ZTA policy.
%% p2_allow/3 facts are injected from Phase 2 final_allow output.
%% effective_deny overrides p2_allow when the current mode and
%% trust state demand it.  effective_allow is the authoritative
%% access decision for downstream enforcement.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

effective_deny(M, C, Op) :-
    p2_allow(M, C, Op),
    current_mode(Mode),
    adaptive_deny(M, C, Mode).

effective_allow(M, C, Op) :-
    p2_allow(M, C, Op),
    not effective_deny(M, C, Op).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 9. DIAGNOSTICS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Signals fired against a node that has no monitor or logging visibility
% are silently discarded from alert_score.  missed_signal/2 exposes them.
% (missed_signal is already defined in section 3 above; no duplicate needed.)

% Signals with no registered weight contribute 0 to alert_score.
% Expose them so mis-typed or unsupported signal kinds are caught.
unknown_signal(N, Signal) :-
    observed(N, Signal, _),
    not signal_weight(Signal, _).

% NOTE: coverage_gap/2 rules are intentionally NOT included here.
% The hard integrity constraints above (:- safety_critical(C), not covered(C). etc.)
% make any model with a coverage gap UNSAT — so coverage_gap predicates can never
% appear in a valid model and would always be empty.  Coverage gap diagnosis is
% performed separately in Python via _diagnose_coverage_gaps().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 10. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show place_monitor/1.
#show active_monitor/1.
#show covered/1.
#show monitor_total_cost/1.
#show observability_score/2.
#show observable/1.
#show missed_signal/2.
#show unknown_signal/2.
#show alert_score/2.
#show anomaly_score/2.
#show trust_state/2.
#show current_mode/1.
#show mode_trigger/2.
#show response_action/2.
#show adaptive_allow/3.
#show adaptive_deny/3.
#show effective_allow/3.
#show effective_deny/3.
