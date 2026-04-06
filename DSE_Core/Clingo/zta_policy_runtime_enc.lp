%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% zta_policy_runtime_enc.lp
%% Purpose: Joint Phase 2 synthesis of ZTA control plane and
%%          runtime observability placement.
%%
%% This file augments zta_policy_enc.lp with monitor placement,
%% observability scoring, and response-readiness objectives.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#include "runtime_monitor_tc9_inst.lp".
#include "zta_policy_enc.lp".

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1. JOINT MONITOR PLACEMENT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

placement_node(N) :- master(N).
placement_node(N) :- receiver(N).
placement_node(N) :- place_ps(N).
placement_node(N) :- place_fw(N).

{ place_monitor(M) : cand_monitor(M) }.

covered(N) :-
    place_monitor(M),
    monitor_covers(M, N).

% Runtime assurance requirements:
%  - safety-critical IPs must be directly observed
%  - every deployed PEP / PS must be observable
:- safety_critical(C), not covered(C).
:- place_ps(PS), not covered(PS).
:- place_fw(FW), not covered(FW).

monitor_total_cost(Cost) :-
    Cost = #sum { C, M : place_monitor(M), monitor_cost(M, C) }.

:- monitor_total_cost(Cost),
   system_capability(max_monitor_cost, MaxCost),
   Cost > MaxCost.

monitor_visibility(N, Score) :-
    placement_node(N),
    Score = #max { S, M : place_monitor(M), monitor_covers(M, N), monitor_strength(M, S);
                   0    : placement_node(N) }.

logging_visibility(C, 0)  :- p1_logging(C, no_logging).
logging_visibility(C, 6)  :- p1_logging(C, some_logging).
logging_visibility(C, 15) :- p1_logging(C, zero_trust_logger).
logging_visibility(N, 0)  :- placement_node(N), not receiver(N).

observability_score(N, Score) :-
    placement_node(N),
    monitor_visibility(N, Mon),
    logging_visibility(N, Log),
    Score = Mon + Log.

detection_latency(N, Latency) :-
    placement_node(N),
    Latency = #min { L, M : place_monitor(M), monitor_covers(M, N), monitor_detection_latency(M, L);
                     999     : placement_node(N) }.

weighted_detection_latency(Total) :-
    Total = #sum { Value, N :
        placement_node(N),
        monitor_priority(N, W),
        detection_latency(N, Lat),
        Value = W * Lat }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 2. RESPONSE READINESS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

response_ready(N) :-
    critical(N),
    covered(N),
    observability_score(N, Score),
    Score > 0.

response_ready(PS) :-
    place_ps(PS),
    covered(PS).

response_ready(FW) :-
    place_fw(FW),
    covered(FW).

response_readiness_score(Score) :-
    Score = #sum { W, N : response_ready(N), monitor_priority(N, W) }.

detection_strength_score(Score) :-
    Score = #sum { Value, N :
        placement_node(N),
        monitor_priority(N, W),
        observability_score(N, Obs),
        Value = W * Obs }.

total_joint_runtime_cost(Total) :-
    total_zta_cost(ZtaCost),
    monitor_total_cost(MonitorCost),
    Total = ZtaCost + MonitorCost.

false_positive_cost(Total) :-
    Total = #sum { Cost, M : place_monitor(M), monitor_false_positive_cost(M, Cost) }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 3. JOINT OBJECTIVE
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#maximize { W@4, N : response_ready(N), monitor_priority(N, W) }.
#maximize { Value@3, N :
    placement_node(N),
    monitor_priority(N, W),
    observability_score(N, Obs),
    Value = W * Obs }.
#minimize { Value@2, N :
    placement_node(N),
    monitor_priority(N, W),
    detection_latency(N, Lat),
    Value = W * Lat }.
#minimize { Cost@1, M : place_monitor(M), monitor_false_positive_cost(M, Cost) }.
#minimize { C@0, M : place_monitor(M), monitor_cost(M, C) }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show place_monitor/1.
#show covered/1.
#show monitor_total_cost/1.
#show observability_score/2.
#show detection_latency/2.
#show response_ready/1.
#show response_readiness_score/1.
#show detection_strength_score/1.
#show weighted_detection_latency/1.
#show false_positive_cost/1.
#show total_joint_runtime_cost/1.
