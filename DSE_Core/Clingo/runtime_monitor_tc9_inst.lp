%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% runtime_monitor_tc9_inst.lp
%% Purpose: Candidate runtime monitors, their costs/strength,
%%          and anomaly signal weights for tc9.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Runtime monitor budget (separate from Phase 1 logic/resource budget)
system_capability(max_monitor_cost, 400).

% Candidate monitors
cand_monitor(mon_noc0).
cand_monitor(mon_noc1).
cand_monitor(mon_ctrl).
cand_monitor(mon_c8).

% Placement cost (abstract implementation cost units)
monitor_cost(mon_noc0, 120).
monitor_cost(mon_noc1, 90).
monitor_cost(mon_ctrl, 110).
monitor_cost(mon_c8, 60).

% Detection strength contribution when the node is covered
monitor_strength(mon_noc0, 8).
monitor_strength(mon_noc1, 8).
monitor_strength(mon_ctrl, 12).
monitor_strength(mon_c8, 18).

% Detection latency in abstract cycles from event to usable alert
monitor_detection_latency(mon_noc0, 3).
monitor_detection_latency(mon_noc1, 3).
monitor_detection_latency(mon_ctrl, 2).
monitor_detection_latency(mon_c8, 1).

% False-positive handling cost (alert fatigue / validation overhead)
monitor_false_positive_cost(mon_noc0, 8).
monitor_false_positive_cost(mon_noc1, 8).
monitor_false_positive_cost(mon_ctrl, 12).
monitor_false_positive_cost(mon_c8, 24).

% Coverage relations
monitor_covers(mon_noc0, sys_cpu).
monitor_covers(mon_noc0, dma).
monitor_covers(mon_noc0, c1).
monitor_covers(mon_noc0, c2).
monitor_covers(mon_noc0, c3).
monitor_covers(mon_noc0, c4).
monitor_covers(mon_noc0, c5).
monitor_covers(mon_noc0, pep_group).

monitor_covers(mon_noc1, dma).
monitor_covers(mon_noc1, c6).
monitor_covers(mon_noc1, c7).
monitor_covers(mon_noc1, c8).
monitor_covers(mon_noc1, pep_standalone).

monitor_covers(mon_ctrl, ps0).
monitor_covers(mon_ctrl, ps1).
monitor_covers(mon_ctrl, pep_group).
monitor_covers(mon_ctrl, pep_standalone).

monitor_covers(mon_c8, c8).

% Weighted coverage objective
monitor_priority(sys_cpu, 25).
monitor_priority(dma, 40).
monitor_priority(c1, 20).
monitor_priority(c2, 20).
monitor_priority(c3, 20).
monitor_priority(c4, 20).
monitor_priority(c5, 20).
monitor_priority(c6, 30).
monitor_priority(c7, 10).
monitor_priority(c8, 50).
monitor_priority(ps0, 40).
monitor_priority(ps1, 30).
monitor_priority(pep_group, 25).
monitor_priority(pep_standalone, 25).

% Runtime anomaly signal weights
signal_weight(rate_spike, 10).
signal_weight(cross_domain, 15).
signal_weight(privilege_creep, 20).
signal_weight(sequence_violation, 25).
signal_weight(policy_violation, 30).
signal_weight(bypass_alert, 35).
signal_weight(attestation_mismatch, 40).
