%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Latency Encoding
% Last Edited: 6/26/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Calculate Latency Costs ----------------------------------

% Calculate combined latency for each asset's read or write operation
asset_latency(A, Action, TotalLatency) :-
    asset(_, A, Action), % Ensure each asset-action pair is selected
    selected_security(A, Security),
    selected_logging(A, Logging),
    latency_cost(Security, SecurityLatency),
    latency_cost(Logging, LoggingLatency),
    TotalLatency = SecurityLatency + LoggingLatency.

#show asset_latency/3.

% End Calculate Latency Costs ------------------------------

