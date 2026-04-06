%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Power accounting driven by Vivado catalog defaults.
%
% The exported security_features_inst.lp now treats:
% - security feature costs as per-component (`byComponent`)
% - logging feature costs as per-component selections via `base`
%
% This encoding therefore counts component-level selections directly and
% avoids the legacy asset-level double counting.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Component-scoped security power
component_power(C, TotalPower) :-
    component(C),
    SecurityComponentPower = #sum { Power : selected_security(C, F), power_cost(F, byComponent, Power) },
    TotalPower = SecurityComponentPower.

#show component_power/2.

total_component_power(ComponentPower) :-
    ComponentPower = #sum { Power, C : component_power(C, Power) }.

#show total_component_power/1.

% Logging and any future security-base terms
base_power_for_component(C, TotalPower) :-
    component(C),
    SecurityBasePower = #sum { Power : selected_security(C, F), power_cost(F, base, Power) },
    LoggingBasePower = #sum { Power : selected_logging(C, L), power_cost(L, base, Power) },
    TotalPower = SecurityBasePower + LoggingBasePower.

total_base_power(BasePower) :-
    BasePower = #sum { Power, C : base_power_for_component(C, Power) }.

#show total_base_power/1.

% Retained for compatibility with existing reports/parsers
total_asset_power(0).
#show total_asset_power/1.

total_power_used(TotalUsedPower) :-
    total_asset_power(TotalAssetPower),
    total_component_power(ComponentPower),
    total_base_power(BasePower),
    TotalUsedPower = TotalAssetPower + ComponentPower + BasePower.

#show total_power_used/1.

:- total_power_used(TotalUsedPower),
   system_capability(max_power, MaxPower),
   TotalUsedPower > MaxPower.
