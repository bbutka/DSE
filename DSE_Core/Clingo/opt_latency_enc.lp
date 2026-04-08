%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: [Author]
% File: Optimize for Latency Encoding
% Last Edited: 4/8/2026
% Purpose: Calculate and optimize selected security and
%          realtime-detection features based on asset risk
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Calculate Latency Costs ----------------------------------

% Calculate combined latency for each asset's read or write operation
asset_latency(A, Action, TotalLatency) :-
    asset(C, A, Action),
    selected_security(C, Security),
    selected_realtime(C, Realtime),
    latency_cost(Security, SecurityLatency),
    latency_cost(Realtime, RealtimeLatency),
    TotalLatency = SecurityLatency + RealtimeLatency.

#show asset_latency/3.

% End Calculate Latency Costs ------------------------------
