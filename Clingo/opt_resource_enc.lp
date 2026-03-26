%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Optimize for Resources Encoding
% Last Edited: 6/24/2025
% Purpose: Provide and optimize for resource utilization of:
%			LUT, FF, DSP, LUTRAM, BUFG
% Missing: 
%		- Logging resource utilization missing  
%       - All optimizations should include a "User Estimate" 
%			to ensure the security + existing system does 
%			not exceed target device constraints
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%





% Look-Up Table Optimization -------------------------------

% Calculate LUT utilization for each asset
luts_used(A, Lut) :- selected_security(A, mac), luts(mac, Lut).
luts_used(A, Lut) :- selected_security(A, dynamic_mac), luts(dynamic_mac, Lut).
luts_used(A, Lut) :- selected_security(A, zero_trust), luts(zero_trust, Lut).

% Sum up LUTs used by all assets
total_luts(TotalLUTs) :- TotalLUTs = #sum { Lut, A : luts_used(A, Lut) }.

% Calculate if base LUTs are needed for dynamic_mac
base_lut_dynamic_mac(Count) :- Count = #count { A : selected_security(A, dynamic_mac) }, Count > 0.

% Calculate if base LUTs are needed for zero_trust
base_lut_zero_trust(Count) :- Count = #count { A : selected_security(A, zero_trust) }, Count > 0.

% Base LUTs for dynamic_mac
base_lut_total_dynamic_mac(Lut) :- base_lut_dynamic_mac(Count), Count > 0, luts(dynamic_mac_base, Lut).

% Base LUTs for zero_trust
base_lut_total_zero_trust(Lut) :- base_lut_zero_trust(Count), Count > 0, luts(zero_trust_base, Lut).

% Calculate total base LUTs
total_base_luts(BaseLUTs) :- 
    BaseLUTs = #sum { Lut : base_lut_total_dynamic_mac(Lut); Lut : base_lut_total_zero_trust(Lut) }.

% Combine total LUTs from features and base LUTs
total_luts_used(TotalUsedLUTs) :- 
    total_luts(TotalLUTs), 
    total_base_luts(BaseLUTs), 
    TotalUsedLUTs = TotalLUTs + BaseLUTs.

#show total_luts_used/1.

% Ensure that the total number of LUTs used does not exceed the system's maximum allowable LUTs
:- total_luts_used(TotalLUTs), system_capability(max_luts, MaxLUTs), TotalLUTs > MaxLUTs.

% End Look-Up Table Optimization ---------------------------





% Flip-Flop Optimization -----------------------------------

% Calculate FFs utilization for each asset type
ffs_used(A, FF) :- selected_security(A, mac), ffs(mac, FF).
ffs_used(A, FF) :- selected_security(A, dynamic_mac), ffs(dynamic_mac, FF).
ffs_used(A, FF) :- selected_security(A, zero_trust), ffs(zero_trust, FF).

% Calculate the base FFs needed for dynamic_mac and zero_trust only if they are selected
base_ff_dynamic_mac(Count) :- Count = #count { A : selected_security(A, dynamic_mac) }, Count > 0.
base_ff_zero_trust(Count) :- Count = #count { A : selected_security(A, zero_trust) }, Count > 0.

% Base FFs for dynamic_mac or zero_trust
base_ff_total_dynamic_mac(FF) :- base_ff_dynamic_mac(Count), Count > 0, ffs(dynamic_mac_base, FF).
base_ff_total_zero_trust(FF) :- base_ff_zero_trust(Count), Count > 0, ffs(zero_trust_base, FF).

% Aggregate FFs used in the entire system
total_ffs(TotalFFs) :- 
    TotalFFs = #sum { FF, A : ffs_used(A, FF) }.

total_base_ffs(BaseFFs) :-
    BaseFFs = #sum { FF : base_ff_total_dynamic_mac(FF); FF : base_ff_total_zero_trust(FF) }.

% Combine total FFs from features and base FFs
total_ffs_used(TotalUsedFFs) :- 
    total_ffs(TotalFFs), 
    total_base_ffs(BaseFFs), 
    TotalUsedFFs = TotalFFs + BaseFFs.

#show total_ffs_used/1.

% Ensure that the total number of FFs used does not exceed the system's maximum allowable FFs
:- total_ffs_used(TotalUsedFFs), system_capability(max_ffs, MaxFFs), TotalUsedFFs > MaxFFs.

% End Flip-Flop Optimization -------------------------------





% DSP Block Optimization ------------------------------------

% Calculate DSPs utilization for each asset
dsps_used(A, DSP) :- selected_security(A, mac), dsps(mac, DSP).
dsps_used(A, DSP) :- selected_security(A, dynamic_mac), dsps(dynamic_mac, DSP).
dsps_used(A, DSP) :- selected_security(A, zero_trust), dsps(zero_trust, DSP).

% Calculate the base DSPs needed for dynamic_mac and zero_trust only if they are selected
base_dsp_dynamic_mac(Count) :- Count = #count { A : selected_security(A, dynamic_mac) }, Count > 0.
base_dsp_zero_trust(Count) :- Count = #count { A : selected_security(A, zero_trust) }, Count > 0.

% Base DSPs for dynamic_mac or zero_trust
base_dsp_total_dynamic_mac(DSP) :- base_dsp_dynamic_mac(Count), Count > 0, dsps(dynamic_mac_base, DSP).
base_dsp_total_zero_trust(DSP) :- base_dsp_zero_trust(Count), Count > 0, dsps(zero_trust_base, DSP).

% Aggregate DSPs used in the entire system
total_dsps(TotalDSPs) :- 
    TotalDSPs = #sum { DSP, A : dsps_used(A, DSP) }.

total_base_dsps(BaseDSPs) :-
    BaseDSPs = #sum { DSP : base_dsp_total_dynamic_mac(DSP); DSP : base_dsp_total_zero_trust(DSP) }.

% Combine total DSPs from features and base DSPs
total_dsps_used(TotalUsedDSPs) :- 
    total_dsps(TotalDSPs), 
    total_base_dsps(BaseDSPs), 
    TotalUsedDSPs = TotalDSPs + BaseDSPs.

#show total_dsps_used/1.

% Ensure that the total number of DSPs used does not exceed the system's maximum allowable DSPs
:- total_dsps_used(TotalUsedDSPs), system_capability(max_dsps, MaxDSPs), TotalUsedDSPs > MaxDSPs.

% End DSP Block Optimization --------------------------------





% LUTRAM Optimization -----------------------------------

% Calculate LUTRAMs utilization for each asset
lutram_used(A, LUTRAM) :- selected_security(A, mac), lutram(mac, LUTRAM).
lutram_used(A, LUTRAM) :- selected_security(A, dynamic_mac), lutram(dynamic_mac, LUTRAM).
lutram_used(A, LUTRAM) :- selected_security(A, zero_trust), lutram(zero_trust, LUTRAM).

% Calculate the base LUTRAMs needed for dynamic_mac and zero_trust only if they are selected
base_lutram_dynamic_mac(Count) :- Count = #count { A : selected_security(A, dynamic_mac) }, Count > 0.
base_lutram_zero_trust(Count) :- Count = #count { A : selected_security(A, zero_trust) }, Count > 0.

% Base LUTRAMs for dynamic_mac or zero_trust
base_lutram_total_dynamic_mac(LUTRAM) :- base_lutram_dynamic_mac(Count), Count > 0, lutram(dynamic_mac_base, LUTRAM).
base_lutram_total_zero_trust(LUTRAM) :- base_lutram_zero_trust(Count), Count > 0, lutram(zero_trust_base, LUTRAM).

% Aggregate LUTRAMs used in the entire system
total_lutram(TotalLUTRAM) :- 
    TotalLUTRAM = #sum { LUTRAM, A : lutram_used(A, LUTRAM) }.

total_base_lutram(BaseLUTRAMs) :-
    BaseLUTRAMs = #sum { LUTRAM : base_lutram_total_dynamic_mac(LUTRAM); LUTRAM : base_lutram_total_zero_trust(LUTRAM) }.

% Combine total LUTRAMs from features and base LUTRAMs
total_lutram_used(TotalUsedLUTRAMs) :- 
    total_lutram(TotalLUTRAM), 
    total_base_lutram(BaseLUTRAMs), 
    TotalUsedLUTRAMs = TotalLUTRAM + BaseLUTRAMs.

#show total_lutram_used/1.

% Ensure that the total number of LUTRAMs used does not exceed the system's maximum allowable LUTRAMs
:- total_lutram_used(TotalUsedLUTRAMs), system_capability(max_lutram, MaxLUTRAMs), TotalUsedLUTRAMs > MaxLUTRAMs.

% End LUTRAM Optimization -------------------------------




% BUFG Optimization -------------------------------------

% Calculate BUFGs utilization for each asset
bufg_used(A, BUFG) :- selected_security(A, mac), bufg(mac, BUFG).
bufg_used(A, BUFG) :- selected_security(A, dynamic_mac), bufg(dynamic_mac, BUFG).
bufg_used(A, BUFG) :- selected_security(A, zero_trust), bufg(zero_trust, BUFG).

% Calculate the base BUFGs needed for dynamic_mac and zero_trust only if they are selected
base_bufg_dynamic_mac(Count) :- Count = #count { A : selected_security(A, dynamic_mac) }, Count > 0.
base_bufg_zero_trust(Count) :- Count = #count { A : selected_security(A, zero_trust) }, Count > 0.

% Base BUFGs for dynamic_mac or zero_trust
base_bufg_total_dynamic_mac(BUFG) :- base_bufg_dynamic_mac(Count), Count > 0, bufg(dynamic_mac_base, BUFG).
base_bufg_total_zero_trust(BUFG) :- base_bufg_zero_trust(Count), Count > 0, bufg(zero_trust_base, BUFG).

% Aggregate BUFGs used in the entire system
total_bufgs(TotalBUFGs) :- 
    TotalBUFGs = #sum { BUFG, A : bufg_used(A, BUFG) }.

total_base_bufgs(BaseBUFGs) :-
    BaseBUFGs = #sum { BUFG : base_bufg_total_dynamic_mac(BUFG); BUFG : base_bufg_total_zero_trust(BUFG) }.

% Combine total BUFGs from features and base BUFGs
total_bufgs_used(TotalUsedBUFGs) :- 
    total_bufgs(TotalBUFGs), 
    total_base_bufgs(BaseBUFGs), 
    TotalUsedBUFGs = TotalBUFGs + BaseBUFGs.

#show total_bufgs_used/1.

% Ensure that the total number of BUFGs used does not exceed the system's maximum allowable BUFGs
:- total_bufgs_used(TotalUsedBUFGs), system_capability(max_bufgs, MaxBUFGs), TotalUsedBUFGs > MaxBUFGs.

% End BUFG Optimization ---------------------------------
