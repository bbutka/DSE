%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Security Encoding
% Last Edited: 6/24/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
% Missing: 
%		- Need to add method of preventing certain security	
%			and logging combinations. 
%		- This might just be an issue with the metric though.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Specify that the zer
:- selected_security(A, zero_trust), not selected_logging(A, zero_trust_logger).
%:- selected_logging(A, zero_trust_logger), not selected_security(A, mac).


% Calculate Asset Risk

#show impact/3.
#show asset/3.

% This was added due to operation undefined error, however all multiplication is correctly performed
% Ignoring the error for now until the root cause is identified
test_risk(Asset, Action, Impact, Prob) :-
    asset(Component, Asset, Action),
    impact(Asset, Action, Impact),
    new_component_probability(Component, Action, Prob).

#show test_risk/4.

new_register_risk(Asset, Action, Impact) :-
    test_risk(Asset, Action, Impact, Prob),
    Risk = Impact * Prob.

#show new_register_risk/3.

% Calculate risk for each asset for read or write then make it a fact so the value can be manipulated
original_register_risk(Asset, Action, Risk) :-
    asset(_, Asset, Action),
    selected_security(Asset, Security),
    selected_logging(Asset, LogFeature),
    vulnerability(Security, Vulnerability),
    logging(LogFeature, LogFactor),
    impact(Asset, Action, Impact),
    Risk = Impact * Vulnerability * LogFactor.

original_register_risk_fact(Asset, Action, Risk) :- original_register_risk(Asset, Action, Risk).
#show original_register_risk_fact/3.


% End Calculate Asset Risk ---------------------------------



% Minimize Total Asset Risk --------------------------------

% Ensure that the risk for each asset does not exceed the maximum allowable risk
%:-original_register_risk(_, _, Risk), system_capability(max_asset_risk, MaxRisk), Risk > MaxRisk.
%#show original_register_risk/3.
:-new_risk(_,_, _, Risk), system_capability(max_asset_risk, MaxRisk), Risk > MaxRisk.
#show new_risk/4.


%#minimize { Risk, Asset :original_register_risk(Asset, Action, Risk) }.
#minimize { Risk, Asset :new_risk(C,Asset, Action, Risk) }.


% End Minimize Total Asset Risk ----------------------------



% Calculate Component Read Risk ----------------------------

% Calculate highest read risk for each component
component_read_risk(Component, MaxReadRisk) :-
    component(Component),
    MaxReadRisk = #max { Risk : asset(Component, Asset, read),original_register_risk(Asset, read, Risk) }.

#show component_read_risk/2.

% End Calculate Component Read Risk ------------------------


% Calculate Component Write Risk ---------------------------

% Calculate highest write risk for each component
component_write_risk(Component, MaxWriteRisk) :-
    component(Component),
    MaxWriteRisk = #max { Risk : asset(Component, Asset, write),original_register_risk(Asset, write, Risk) }.

#show component_write_risk/2.

% End Calculate Component Write Risk -----------------------
