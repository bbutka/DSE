%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Power Encoding
% Last Edited: 6/26/2025
% Purpose: Calculate and optimize selected security and 
%			logging	features based on asset risk
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Calculate Power Costs ------------------------------------

% Calculate power utilization for each asset
power_used(A, Power) :- selected_security(A, mac), power_cost(mac, byAsset, Power).
power_used(A, Power) :- selected_security(A, dynamic_mac), power_cost(dynamic_mac, byAsset, Power).
power_used(A, Power) :- selected_security(A, zero_trust), power_cost(zero_trust, byAsset, Power).

% Sum up power used by all assets
total_asset_power(TotalAssetPower) :- TotalAssetPower = #sum { Power, A : power_used(A, Power) }.

#show total_asset_power/1.

% Total base power cost
total_base_power(BasePower) :-
    BaseDynamicMac = #sum { Power : selected_security(A, dynamic_mac), power_cost(dynamic_mac, base, Power) },
    BaseZeroTrust = #sum { Power : selected_security(A, zero_trust), power_cost(zero_trust, base, Power) },
    BaseSomeLogging = #sum { Power : selected_logging(A, some_logging), power_cost(some_logging, base, Power) },
    BaseZeroTrustLogging = #sum { Power : selected_logging(A, zero_trust_logger), power_cost(zero_trust_logger, base, Power) },
    BasePower = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.
#show total_base_power/1.

% Power used by each component
component_power(C, TotalPower) :-
    component(C),
    ComponentMacPower = #sum { Power : asset(C, A, _), selected_security(A, mac), power_cost(mac, byComponent, Power) },
    ComponentDynamicMacPower = #sum { Power : asset(C, A, _), selected_security(A, dynamic_mac), power_cost(dynamic_mac, byComponent, Power) },
    ComponentZeroTrustPower = #sum { Power : asset(C, A, _), selected_security(A, zero_trust), power_cost(zero_trust, byComponent, Power) },
    TotalPower = ComponentMacPower + ComponentDynamicMacPower + ComponentZeroTrustPower.

#show component_power/2.

% Sum total power used by components
total_component_power(ComponentPower) :- ComponentPower = #sum { Power, C : component_power(C, Power) }.

#show total_component_power/1.

% Combine total power from features and base power
total_power_used(TotalUsedPower) :- 
    total_asset_power(TotalAssetPower),
    total_component_power(ComponentPower),
    total_base_power(BasePower),
    TotalUsedPower = TotalAssetPower + ComponentPower + BasePower.

#show total_power_used/1.

% Ensure that the total power does not exceed the system's maximum allowable power
:- total_power_used(TotalUsedPower), system_capability(max_power, MaxPower), TotalUsedPower > MaxPower.

% End Calculate Power Costs --------------------------------
