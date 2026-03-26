%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Security Encoding
% Last Edited: 6/24/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
% Missing: 
%		- Read and write risk 
%       - No "component" risk calculated
%		- Need to add method of preventing certain security	
%			and logging combinations. 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Calculate Asset Risk -------------------------------------

% Calculate risk for each asset then make it a fact so the value can be manipulated
register_risk(Register, Risk) :-
    asset(_, Register),
    impact(Register, Impact),
    selected_security(Register, Security),
    selected_logging(Register, LogFeature),
    vulnerability(Security, Vulnerability),
    logging(LogFeature, LogFactor),
    Risk = Impact * Vulnerability * LogFactor.
register_risk_fact(Register, Risk) :- register_risk(Register, Risk).
#show register_risk_fact/2.

% Ensure that the risk for each asset does not exceed the maximum allowable risk
:- register_risk_fact(A, Risk), system_capability(max_asset_risk, MaxRisk), Risk > MaxRisk.

% Minimization: minimize the total risk over all assets
#minimize { Risk, A : register_risk_fact(A, Risk) }.

% End Calculate Asset Risk ---------------------------------
