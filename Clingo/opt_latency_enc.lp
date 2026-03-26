%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Security Encoding
% Last Edited: 6/24/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
% Missing: 
%		- Read and write risk 
%       - No "component" risk calculated
%		- Currently it is totalling all latencies. 
%			It needs to total per asset latency, like risk
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Calculate Latency Costs ----------------------------------

% Calculate latency for each selected security feature
security_latency(A, Latency) :- selected_security(A, Security), latency_cost(Security, Latency).

% Calculate latency for each selected logging feature
logging_latency(A, Latency) :- selected_logging(A, Logging), latency_cost(Logging, Latency).

% Sum up latencies for all selected security and logging features
total_security_latency(TotalSecurityLatency) :- 
    TotalSecurityLatency = #sum { Latency, A : security_latency(A, Latency) }.

total_logging_latency(TotalLoggingLatency) :-
    TotalLoggingLatency = #sum { Latency, A : logging_latency(A, Latency) }.

% Combine total latencies from security and logging features
total_latency(TotalLatency) :- 
    total_security_latency(TotalSecurityLatency), 
    total_logging_latency(TotalLoggingLatency), 
    TotalLatency = TotalSecurityLatency + TotalLoggingLatency.

% Ensure that the total latency does not exceed the system's maximum allowable latency
:- total_latency(TotalLatency), system_capability(max_latency, MaxLatency), TotalLatency > MaxLatency.

#show total_latency/1.

% End Calculate Latency Costs ------------------------------