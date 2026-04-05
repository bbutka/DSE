%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Latency Encoding
% Last Edited: 6/26/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Calculate Latency Costs ----------------------------------

% Calculate hard latency for each asset's read or write operation.
%
% The active HOST26 timing constraint is component-security driven:
% each asset inherits the selected security feature of its owning component
% via bridge_enc.lp, and the hard budget is checked against that security
% feature's latency only.
%
% Logging overhead is intentionally excluded from this hard constraint.
% The logging path is not modeled here as a constant per-access delay.
asset_latency(A, Action, TotalLatency) :-
    asset(_, A, Action), % Ensure each asset-action pair is selected
    selected_security(A, Security),
    latency_cost(Security, SecurityLatency),
    TotalLatency = SecurityLatency.

#show asset_latency/3.

% End Calculate Latency Costs ------------------------------

