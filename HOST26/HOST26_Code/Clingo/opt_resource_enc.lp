%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Resources Encoding
% Last Edited: 6/26/2025
% Purpose: Provide and optimize for resource utilization of:
%			LUT, FF, DSP, LUTRAM, BUFG
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%





% Look-Up Table Optimization -------------------------------

% Calculate LUT utilization for each asset register (guard on asset/3 prevents
% double-counting the component-level selected_security/2 atoms from bridge_enc.lp)
luts_used(A, Lut) :- asset(_, A, _), selected_security(A, mac), luts(mac, byAsset, Lut).
luts_used(A, Lut) :- asset(_, A, _), selected_security(A, dynamic_mac), luts(dynamic_mac, byAsset, Lut).
luts_used(A, Lut) :- asset(_, A, _), selected_security(A, zero_trust), luts(zero_trust, byAsset, Lut).

% Sum up LUTs used by all assets
total_asset_luts(TotalAssetLUTs) :- TotalAssetLUTs = #sum { Lut, A : luts_used(A, Lut) }.

%#show total_asset_luts/1.

% Check if base LUTs are needed
base_lut_dynamic_mac :- #count { A : selected_security(A, dynamic_mac) } > 0.
base_lut_zero_trust :- #count { A : selected_security(A, zero_trust) } > 0.
base_zero_trust_logger :- #count { A : selected_logging(A, zero_trust_logger) } > 0.

% Total base LUT cost
total_base_luts(BaseLUTs) :-
    BaseDynamicMac = #sum { Lut : base_lut_dynamic_mac, luts(dynamic_mac, base, Lut) },
    BaseZeroTrust = #sum { Lut : base_lut_zero_trust, luts(zero_trust, base, Lut) },
    BaseLogging = #sum { Lut : selected_logging(A, some_logging), luts(some_logging, base, Lut) },
    BaseZeroTrustLogging = #sum { Lut : base_zero_trust_logger, luts(zero_trust_logger, base, Lut) },
    BaseLUTs = BaseDynamicMac + BaseZeroTrust + BaseLogging + BaseZeroTrustLogging.

%#show total_base_luts/1.

% LUTs used by each component
luts_used_by_component(C, TotalLut) :-
    component(C),
    ComponentMacLut = #sum { Lut : asset(C, A, _), selected_security(A, mac), luts(mac, byComponent, Lut) },
    ComponentDynamicMacLut = #sum { Lut : asset(C, A, _), selected_security(A, dynamic_mac), luts(dynamic_mac, byComponent, Lut) },
    ComponentZeroTrustLut = #sum { Lut : asset(C, A, _), selected_security(A, zero_trust), luts(zero_trust, byComponent, Lut) },
    TotalLut = ComponentMacLut + ComponentDynamicMacLut + ComponentZeroTrustLut.

%#show luts_used_by_component/2.

% Sum total LUTs used by components
total_component_luts(ComponentLUTs) :- ComponentLUTs = #sum { Lut, C : luts_used_by_component(C, Lut) }.

%#show total_component_luts/1.

% Combine total LUTs from features and base LUTs
total_luts_used(TotalUsedLUTs) :-
    total_asset_luts(TotalAssetLUTs),
    total_component_luts(ComponentLUTs),
    total_base_luts(BaseLUTs),
    TotalUsedLUTs = TotalAssetLUTs + ComponentLUTs + BaseLUTs.

#show total_luts_used/1.

% Ensure that the total number of LUTs used does not exceed the system's maximum allowable LUTs
:- total_luts_used(TotalUsedLUTs), system_capability(max_luts, MaxLUTs), TotalUsedLUTs > MaxLUTs.

% End Look-Up Table Optimization ---------------------------





% Flip-Flop Optimization -----------------------------------

% Calculate FFS utilization for each asset register
ffs_used(A, FFS) :- asset(_, A, _), selected_security(A, mac), ffs(mac, byAsset, FFS).
ffs_used(A, FFS) :- asset(_, A, _), selected_security(A, dynamic_mac), ffs(dynamic_mac, byAsset, FFS).
ffs_used(A, FFS) :- asset(_, A, _), selected_security(A, zero_trust), ffs(zero_trust, byAsset, FFS).

% Sum up FFSs used by all assets
total_asset_ffs(TotalAssetFFS) :- TotalAssetFFS = #sum { FFS, A : ffs_used(A, FFS) }.

%#show total_asset_ffs/1.

% Total base FFS cost
total_base_ffs(BaseFFSs) :-
    BaseDynamicMac = #sum { FFS : selected_security(A, dynamic_mac), ffs(dynamic_mac, base, FFS) },
    BaseZeroTrust = #sum { FFS : selected_security(A, zero_trust), ffs(zero_trust, base, FFS) },
    BaseSomeLogging = #sum { FFS : selected_logging(A, some_logging), ffs(some_logging, base, FFS) },
    BaseZeroTrustLogging = #sum { FFS : selected_logging(A, zero_trust_logger), ffs(zero_trust_logger, base, FFS) },
    BaseFFSs = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.

%#show total_base_ffs/1.

% FFSs used by each component
ffs_used_by_component(C, TotalFFS) :-
    component(C),
    ComponentMacFFS = #sum { FFS : asset(C, A, _), selected_security(A, mac), ffs(mac, byComponent, FFS) },
    ComponentDynamicMacFFS = #sum { FFS : asset(C, A, _), selected_security(A, dynamic_mac), ffs(dynamic_mac, byComponent, FFS) },
    ComponentZeroTrustFFS = #sum { FFS : asset(C, A, _), selected_security(A, zero_trust), ffs(zero_trust, byComponent, FFS) },
    TotalFFS = ComponentMacFFS + ComponentDynamicMacFFS + ComponentZeroTrustFFS.

%#show ffs_used_by_component/2.

% Sum total FFSs used by components
total_component_ffs(ComponentFFS) :- ComponentFFS = #sum { FFS, C : ffs_used_by_component(C, FFS) }.

%#show total_component_ffs/1.

% Combine total FFSs from features and base FFSs
total_ffs_used(TotalUsedFFS) :-
    total_asset_ffs(TotalAssetFFS),
    total_component_ffs(ComponentFFS),
    total_base_ffs(BaseFFSs),
    TotalUsedFFS = TotalAssetFFS + ComponentFFS + BaseFFSs.

#show total_ffs_used/1.

% Ensure that the total number of FFSs used does not exceed the system's maximum allowable FFSs
:- total_ffs_used(TotalUsedFFS), system_capability(max_ffs, MaxFFS), TotalUsedFFS > MaxFFS.

% End Flip-Flop Optimization -------------------------------





% DSP Block Optimization ------------------------------------

% Calculate DSPS utilization for each asset register
dsps_used(A, DSPS) :- asset(_, A, _), selected_security(A, mac), dsps(mac, byAsset, DSPS).
dsps_used(A, DSPS) :- asset(_, A, _), selected_security(A, dynamic_mac), dsps(dynamic_mac, byAsset, DSPS).
dsps_used(A, DSPS) :- asset(_, A, _), selected_security(A, zero_trust), dsps(zero_trust, byAsset, DSPS).

% Sum up DSPS used by all assets
total_asset_dsps(TotalAssetDSPS) :- TotalAssetDSPS = #sum { DSPS, A : dsps_used(A, DSPS) }.

%#show total_asset_dsps/1.

% Total base DSPS cost
total_base_dsps(BaseDSPS) :-
    BaseDynamicMac = #sum { DSPS : selected_security(A, dynamic_mac), dsps(dynamic_mac, base, DSPS) },
    BaseZeroTrust = #sum { DSPS : selected_security(A, zero_trust), dsps(zero_trust, base, DSPS) },
    BaseSomeLogging = #sum { DSPS : selected_logging(A, some_logging), dsps(some_logging, base, DSPS) },
    BaseZeroTrustLogging = #sum { DSPS : selected_logging(A, zero_trust_logger), dsps(zero_trust_logger, base, DSPS) },
    BaseDSPS = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.

%#show total_base_dsps/1.

% DSPS used by each component
dsps_used_by_component(C, TotalDSPS) :-
    component(C),
    ComponentMacDSPS = #sum { DSPS : asset(C, A, _), selected_security(A, mac), dsps(mac, byComponent, DSPS) },
    ComponentDynamicMacDSPS = #sum { DSPS : asset(C, A, _), selected_security(A, dynamic_mac), dsps(dynamic_mac, byComponent, DSPS) },
    ComponentZeroTrustDSPS = #sum { DSPS : asset(C, A, _), selected_security(A, zero_trust), dsps(zero_trust, byComponent, DSPS) },
    TotalDSPS = ComponentMacDSPS + ComponentDynamicMacDSPS + ComponentZeroTrustDSPS.

%#show dsps_used_by_component/2.

% Sum total DSPS used by components
total_component_dsps(ComponentDSPS) :- ComponentDSPS = #sum { DSPS, C : dsps_used_by_component(C, DSPS) }.

%#show total_component_dsps/1.

% Combine total DSPS from features and base DSPS
total_dsps_used(TotalUsedDSPS) :-
    total_asset_dsps(TotalAssetDSPS),
    total_component_dsps(ComponentDSPS),
    total_base_dsps(BaseDSPS),
    TotalUsedDSPS = TotalAssetDSPS + ComponentDSPS + BaseDSPS.

#show total_dsps_used/1.

% Ensure that the total number of DSPS used does not exceed the system's maximum allowable DSPS
:- total_dsps_used(TotalUsedDSPS), system_capability(max_dsps, MaxDSPS), TotalUsedDSPS > MaxDSPS.

% End DSP Block Optimization --------------------------------





% LUTRAM Optimization -----------------------------------

% Calculate LUTRAM utilization for each asset register
lutram_used(A, LUTRAM) :- asset(_, A, _), selected_security(A, mac), lutram(mac, byAsset, LUTRAM).
lutram_used(A, LUTRAM) :- asset(_, A, _), selected_security(A, dynamic_mac), lutram(dynamic_mac, byAsset, LUTRAM).
lutram_used(A, LUTRAM) :- asset(_, A, _), selected_security(A, zero_trust), lutram(zero_trust, byAsset, LUTRAM).

% Sum up LUTRAMs used by all assets
total_asset_lutram(TotalAssetLUTRAM) :- TotalAssetLUTRAM = #sum { LUTRAM, A : lutram_used(A, LUTRAM) }.

%#show total_asset_lutram/1.

% Total base LUTRAM cost
total_base_lutram(BaseLUTRAMs) :-
    BaseDynamicMac = #sum { LUTRAM : selected_security(A, dynamic_mac), lutram(dynamic_mac, base, LUTRAM) },
    BaseZeroTrust = #sum { LUTRAM : selected_security(A, zero_trust), lutram(zero_trust, base, LUTRAM) },
    BaseSomeLogging = #sum { LUTRAM : selected_logging(A, some_logging), lutram(some_logging, base, LUTRAM) },
    BaseZeroTrustLogging = #sum { LUTRAM : selected_logging(A, zero_trust_logger), lutram(zero_trust_logger, base, LUTRAM) },
    BaseLUTRAMs = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.

%#show total_base_lutram/1.

% LUTRAMs used by each component
lutram_used_by_component(C, TotalLUTRAM) :-
    component(C),
    ComponentMacLUTRAM = #sum { LUTRAM : asset(C, A, _), selected_security(A, mac), lutram(mac, byComponent, LUTRAM) },
    ComponentDynamicMacLUTRAM = #sum { LUTRAM : asset(C, A, _), selected_security(A, dynamic_mac), lutram(dynamic_mac, byComponent, LUTRAM) },
    ComponentZeroTrustLUTRAM = #sum { LUTRAM : asset(C, A, _), selected_security(A, zero_trust), lutram(zero_trust, byComponent, LUTRAM) },
    TotalLUTRAM = ComponentMacLUTRAM + ComponentDynamicMacLUTRAM + ComponentZeroTrustLUTRAM.

%#show lutram_used_by_component/2.

% Sum total LUTRAMs used by components
total_component_lutram(ComponentLUTRAM) :- ComponentLUTRAM = #sum { LUTRAM, C : lutram_used_by_component(C, LUTRAM) }.

%#show total_component_lutram/1.

% Combine total LUTRAMs from features and base LUTRAMs
total_lutram_used(TotalUsedLUTRAM) :-
    total_asset_lutram(TotalAssetLUTRAM),
    total_component_lutram(ComponentLUTRAM),
    total_base_lutram(BaseLUTRAMs),
    TotalUsedLUTRAM = TotalAssetLUTRAM + ComponentLUTRAM + BaseLUTRAMs.

#show total_lutram_used/1.

% Ensure that the total number of LUTRAMs used does not exceed the system's maximum allowable LUTRAMs
:- total_lutram_used(TotalUsedLUTRAM), system_capability(max_lutram, MaxLUTRAM), TotalUsedLUTRAM > MaxLUTRAM.

% End LUTRAM Optimization -------------------------------




% BUFG Optimization -------------------------------------

% Calculate BUFG utilization for each asset register
bufg_used(A, BUFG) :- asset(_, A, _), selected_security(A, mac), bufg(mac, byAsset, BUFG).
bufg_used(A, BUFG) :- asset(_, A, _), selected_security(A, dynamic_mac), bufg(dynamic_mac, byAsset, BUFG).
bufg_used(A, BUFG) :- asset(_, A, _), selected_security(A, zero_trust), bufg(zero_trust, byAsset, BUFG).

% Sum up BUFGs used by all assets
total_asset_bufg(TotalAssetBUFG) :- TotalAssetBUFG = #sum { BUFG, A : bufg_used(A, BUFG) }.

%#show total_asset_bufg/1.

% Total base BUFG cost
total_base_bufg(BaseBUFGs) :-
    BaseDynamicMac = #sum { BUFG : selected_security(A, dynamic_mac), bufg(dynamic_mac, base, BUFG) },
    BaseZeroTrust = #sum { BUFG : selected_security(A, zero_trust), bufg(zero_trust, base, BUFG) },
    BaseSomeLogging = #sum { BUFG : selected_logging(A, some_logging), bufg(some_logging, base, BUFG) },
    BaseZeroTrustLogging = #sum { BUFG : selected_logging(A, zero_trust_logger), bufg(zero_trust_logger, base, BUFG) },
    BaseBUFGs = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.

%#show total_base_bufg/1.

% BUFGs used by each component
bufg_used_by_component(C, TotalBUFG) :-
    component(C),
    ComponentMacBUFG = #sum { BUFG : asset(C, A, _), selected_security(A, mac), bufg(mac, byComponent, BUFG) },
    ComponentDynamicMacBUFG = #sum { BUFG : asset(C, A, _), selected_security(A, dynamic_mac), bufg(dynamic_mac, byComponent, BUFG) },
    ComponentZeroTrustBUFG = #sum { BUFG : asset(C, A, _), selected_security(A, zero_trust), bufg(zero_trust, byComponent, BUFG) },
    TotalBUFG = ComponentMacBUFG + ComponentDynamicMacBUFG + ComponentZeroTrustBUFG.

%#show bufg_used_by_component/2.

% Sum total BUFGs used by components
total_component_bufg(ComponentBUFG) :- ComponentBUFG = #sum { BUFG, C : bufg_used_by_component(C, BUFG) }.

%#show total_component_bufg/1.

% Combine total BUFGs from features and base BUFGs
total_bufg_used(TotalUsedBUFG) :-
    total_asset_bufg(TotalAssetBUFG),
    total_component_bufg(ComponentBUFG),
    total_base_bufg(BaseBUFGs),
    TotalUsedBUFG = TotalAssetBUFG + ComponentBUFG + BaseBUFGs.

%#show total_bufg_used/1.

% Ensure that the total number of BUFGs used does not exceed the system's maximum allowable BUFGs
:- total_bufg_used(TotalUsedBUFG), system_capability(max_bufg, MaxBUFG), TotalUsedBUFG > MaxBUFG.

% End BUFG Optimization ---------------------------------





% Block RAM (BRAM) Optimization -------------------------

% Calculate BRAM utilization for each asset register
bram_used(A, BRAM) :- asset(_, A, _), selected_security(A, mac), bram(mac, byAsset, BRAM).
bram_used(A, BRAM) :- asset(_, A, _), selected_security(A, dynamic_mac), bram(dynamic_mac, byAsset, BRAM).
bram_used(A, BRAM) :- asset(_, A, _), selected_security(A, zero_trust), bram(zero_trust, byAsset, BRAM).

% Sum up BRAMs used by all assets
total_asset_bram(TotalAssetBRAM) :- TotalAssetBRAM = #sum { BRAM, A : bram_used(A, BRAM) }.

%#show total_asset_bram/1.

% Total base BRAM cost
total_base_bram(BaseBRAMs) :-
    BaseDynamicMac = #sum { BRAM : selected_security(A, dynamic_mac), bram(dynamic_mac, base, BRAM) },
    BaseZeroTrust = #sum { BRAM : selected_security(A, zero_trust), bram(zero_trust, base, BRAM) },
    BaseSomeLogging = #sum { BRAM : selected_logging(A, some_logging), bram(some_logging, base, BRAM) },
    BaseZeroTrustLogging = #sum { BRAM : selected_logging(A, zero_trust_logger), bram(zero_trust_logger, base, BRAM) },
    BaseBRAMs = BaseDynamicMac + BaseZeroTrust + BaseSomeLogging + BaseZeroTrustLogging.

%#show total_base_bram/1.

% BRAMs used by each component
bram_used_by_component(C, TotalBRAM) :-
    component(C),
    ComponentMacBRAM = #sum { BRAM : asset(C, A, _), selected_security(A, mac), bram(mac, byComponent, BRAM) },
    ComponentDynamicMacBRAM = #sum { BRAM : asset(C, A, _), selected_security(A, dynamic_mac), bram(dynamic_mac, byComponent, BRAM) },
    ComponentZeroTrustBRAM = #sum { BRAM : asset(C, A, _), selected_security(A, zero_trust), bram(zero_trust, byComponent, BRAM) },
    TotalBRAM = ComponentMacBRAM + ComponentDynamicMacBRAM + ComponentZeroTrustBRAM.

%#show bram_used_by_component/2.

% Sum total BRAMs used by components
total_component_bram(ComponentBRAM) :- ComponentBRAM = #sum { BRAM, C : bram_used_by_component(C, BRAM) }.

%#show total_component_bram/1.

% Combine total BRAMs from features and base BRAMs
total_bram_used(TotalUsedBRAM) :-
    total_asset_bram(TotalAssetBRAM),
    total_component_bram(ComponentBRAM),
    total_base_bram(BaseBRAMs),
    TotalUsedBRAM = TotalAssetBRAM + ComponentBRAM + BaseBRAMs.

#show total_bram_used/1.

% Ensure that the total number of BRAMs used does not exceed the system's maximum allowable BRAMs
:- total_bram_used(TotalUsedBRAM), system_capability(max_bram, MaxBRAM), TotalUsedBRAM > MaxBRAM.

% End Block RAM (BRAM) Optimization ---------------------
