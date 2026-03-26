%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Power Encoding
% Last Edited: 6/24/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
% Missing: 
%		- Read and write risk 
%       - No "component" risk calculated
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Calculate Power Costs ------------------------------------

% Calculate the sum of power costs for selected logging features
logging_feature_power(LoggingTotal) :- 
    LoggingTotal = #sum { FeaturePower : selected_logging(A, L), power_cost(L, FeaturePower) }.
#show logging_feature_power/1.



% Calculate the sum of power costs for selected security features
security_feature_power(SecurityTotal) :-
    SecurityTotal = #sum { FeaturePower : selected_security(A, F), power_cost(F, FeaturePower) }.
#show security_feature_power/1.



% Declare logging and security powers as facts to show them
logging_power(LoggingTotal) :- logging_feature_power(LoggingTotal).
security_power(SecurityTotal) :- security_feature_power(SecurityTotal).
#show logging_power/1.
#show security_power/1.



% Sum all power costs
total_feature_power(TotalPower) :- 
    logging_feature_power(LoggingTotal),
    security_feature_power(SecurityTotal),   
    TotalPower = LoggingTotal + SecurityTotal.

% Ensure that the total power does not exceed the system's maximum allowable power
:- total_feature_power(TotalPower), system_capability(max_power, MaxPower), TotalPower > MaxPower.

#show total_feature_power/1.

% End Calculate Power Costs --------------------------------
