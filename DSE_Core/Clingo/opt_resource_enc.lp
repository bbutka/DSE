%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Resource accounting driven by Vivado catalog defaults.
%
% The exported security_features_inst.lp maps Vivado totals as:
% - security feature cost -> byComponent
% - realtime-detection feature cost -> base (counted once per selected component)
%
% This encoding counts component-level selections directly and preserves the
% existing output atoms (total_asset_*, total_component_*, total_base_*,
% total_*_used) so the surrounding tooling does not have to change.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% LUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

luts_used_by_component(C, TotalLut) :-
    component(C),
    TotalLut = #sum { Lut : selected_security(C, F), luts(F, byComponent, Lut) }.

total_component_luts(ComponentLUTs) :-
    ComponentLUTs = #sum { Lut, C : luts_used_by_component(C, Lut) }.

security_base_luts_for_component(C, TotalLut) :-
    component(C),
    TotalLut = #sum { Lut : selected_security(C, F), luts(F, base, Lut) }.

realtime_base_luts_for_component(C, TotalLut) :-
    component(C),
    TotalLut = #sum { Lut : selected_realtime(C, L), luts(L, base, Lut) }.

total_base_luts(BaseLUTs) :-
    SecurityBaseLUTs = #sum { Lut, C : security_base_luts_for_component(C, Lut) },
    RealtimeBaseLUTs = #sum { Lut, C : realtime_base_luts_for_component(C, Lut) },
    BaseLUTs = SecurityBaseLUTs + RealtimeBaseLUTs.

total_asset_luts(0).

total_luts_used(TotalUsedLUTs) :-
    total_asset_luts(TotalAssetLUTs),
    total_component_luts(ComponentLUTs),
    total_base_luts(BaseLUTs),
    TotalUsedLUTs = TotalAssetLUTs + ComponentLUTs + BaseLUTs.

#show total_luts_used/1.

:- total_luts_used(TotalUsedLUTs),
   system_capability(max_luts, MaxLUTs),
   TotalUsedLUTs > MaxLUTs.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% FFS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

ffs_used_by_component(C, TotalFFS) :-
    component(C),
    TotalFFS = #sum { FFS : selected_security(C, F), ffs(F, byComponent, FFS) }.

total_component_ffs(ComponentFFS) :-
    ComponentFFS = #sum { FFS, C : ffs_used_by_component(C, FFS) }.

security_base_ffs_for_component(C, TotalFFS) :-
    component(C),
    TotalFFS = #sum { FFS : selected_security(C, F), ffs(F, base, FFS) }.

realtime_base_ffs_for_component(C, TotalFFS) :-
    component(C),
    TotalFFS = #sum { FFS : selected_realtime(C, L), ffs(L, base, FFS) }.

total_base_ffs(BaseFFSs) :-
    SecurityBaseFFSs = #sum { FFS, C : security_base_ffs_for_component(C, FFS) },
    RealtimeBaseFFSs = #sum { FFS, C : realtime_base_ffs_for_component(C, FFS) },
    BaseFFSs = SecurityBaseFFSs + RealtimeBaseFFSs.

total_asset_ffs(0).

total_ffs_used(TotalUsedFFS) :-
    total_asset_ffs(TotalAssetFFS),
    total_component_ffs(ComponentFFS),
    total_base_ffs(BaseFFSs),
    TotalUsedFFS = TotalAssetFFS + ComponentFFS + BaseFFSs.

#show total_ffs_used/1.

:- total_ffs_used(TotalUsedFFS),
   system_capability(max_ffs, MaxFFS),
   TotalUsedFFS > MaxFFS.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% DSPS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

dsps_used_by_component(C, TotalDSPS) :-
    component(C),
    TotalDSPS = #sum { DSPS : selected_security(C, F), dsps(F, byComponent, DSPS) }.

total_component_dsps(ComponentDSPS) :-
    ComponentDSPS = #sum { DSPS, C : dsps_used_by_component(C, DSPS) }.

security_base_dsps_for_component(C, TotalDSPS) :-
    component(C),
    TotalDSPS = #sum { DSPS : selected_security(C, F), dsps(F, base, DSPS) }.

realtime_base_dsps_for_component(C, TotalDSPS) :-
    component(C),
    TotalDSPS = #sum { DSPS : selected_realtime(C, L), dsps(L, base, DSPS) }.

total_base_dsps(BaseDSPS) :-
    SecurityBaseDSPS = #sum { DSPS, C : security_base_dsps_for_component(C, DSPS) },
    RealtimeBaseDSPS = #sum { DSPS, C : realtime_base_dsps_for_component(C, DSPS) },
    BaseDSPS = SecurityBaseDSPS + RealtimeBaseDSPS.

total_asset_dsps(0).

total_dsps_used(TotalUsedDSPS) :-
    total_asset_dsps(TotalAssetDSPS),
    total_component_dsps(ComponentDSPS),
    total_base_dsps(BaseDSPS),
    TotalUsedDSPS = TotalAssetDSPS + ComponentDSPS + BaseDSPS.

#show total_dsps_used/1.

:- total_dsps_used(TotalUsedDSPS),
   system_capability(max_dsps, MaxDSPS),
   TotalUsedDSPS > MaxDSPS.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% LUTRAM
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

lutram_used_by_component(C, TotalLUTRAM) :-
    component(C),
    TotalLUTRAM = #sum { LUTRAM : selected_security(C, F), lutram(F, byComponent, LUTRAM) }.

total_component_lutram(ComponentLUTRAM) :-
    ComponentLUTRAM = #sum { LUTRAM, C : lutram_used_by_component(C, LUTRAM) }.

security_base_lutram_for_component(C, TotalLUTRAM) :-
    component(C),
    TotalLUTRAM = #sum { LUTRAM : selected_security(C, F), lutram(F, base, LUTRAM) }.

realtime_base_lutram_for_component(C, TotalLUTRAM) :-
    component(C),
    TotalLUTRAM = #sum { LUTRAM : selected_realtime(C, L), lutram(L, base, LUTRAM) }.

total_base_lutram(BaseLUTRAMs) :-
    SecurityBaseLUTRAMs = #sum { LUTRAM, C : security_base_lutram_for_component(C, LUTRAM) },
    RealtimeBaseLUTRAMs = #sum { LUTRAM, C : realtime_base_lutram_for_component(C, LUTRAM) },
    BaseLUTRAMs = SecurityBaseLUTRAMs + RealtimeBaseLUTRAMs.

total_asset_lutram(0).

total_lutram_used(TotalUsedLUTRAM) :-
    total_asset_lutram(TotalAssetLUTRAM),
    total_component_lutram(ComponentLUTRAM),
    total_base_lutram(BaseLUTRAMs),
    TotalUsedLUTRAM = TotalAssetLUTRAM + ComponentLUTRAM + BaseLUTRAMs.

#show total_lutram_used/1.

:- total_lutram_used(TotalUsedLUTRAM),
   system_capability(max_lutram, MaxLUTRAM),
   TotalUsedLUTRAM > MaxLUTRAM.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% BUFG
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

bufg_used_by_component(C, TotalBUFG) :-
    component(C),
    TotalBUFG = #sum { BUFG : selected_security(C, F), bufg(F, byComponent, BUFG) }.

total_component_bufg(ComponentBUFG) :-
    ComponentBUFG = #sum { BUFG, C : bufg_used_by_component(C, BUFG) }.

security_base_bufg_for_component(C, TotalBUFG) :-
    component(C),
    TotalBUFG = #sum { BUFG : selected_security(C, F), bufg(F, base, BUFG) }.

realtime_base_bufg_for_component(C, TotalBUFG) :-
    component(C),
    TotalBUFG = #sum { BUFG : selected_realtime(C, L), bufg(L, base, BUFG) }.

total_base_bufg(BaseBUFGs) :-
    SecurityBaseBUFGs = #sum { BUFG, C : security_base_bufg_for_component(C, BUFG) },
    RealtimeBaseBUFGs = #sum { BUFG, C : realtime_base_bufg_for_component(C, BUFG) },
    BaseBUFGs = SecurityBaseBUFGs + RealtimeBaseBUFGs.

total_asset_bufg(0).

total_bufg_used(TotalUsedBUFG) :-
    total_asset_bufg(TotalAssetBUFG),
    total_component_bufg(ComponentBUFG),
    total_base_bufg(BaseBUFGs),
    TotalUsedBUFG = TotalAssetBUFG + ComponentBUFG + BaseBUFGs.

bufg_capacity(MaxBUFG) :- system_capability(max_bufgs, MaxBUFG).
bufg_capacity(MaxBUFG) :- system_capability(max_bufg, MaxBUFG),
                          not system_capability(max_bufgs, _).

:- total_bufg_used(TotalUsedBUFG),
   bufg_capacity(MaxBUFG),
   TotalUsedBUFG > MaxBUFG.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% BRAM
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

bram_used_by_component(C, TotalBRAM) :-
    component(C),
    TotalBRAM = #sum { BRAM : selected_security(C, F), bram(F, byComponent, BRAM) }.

total_component_bram(ComponentBRAM) :-
    ComponentBRAM = #sum { BRAM, C : bram_used_by_component(C, BRAM) }.

security_base_bram_for_component(C, TotalBRAM) :-
    component(C),
    TotalBRAM = #sum { BRAM : selected_security(C, F), bram(F, base, BRAM) }.

realtime_base_bram_for_component(C, TotalBRAM) :-
    component(C),
    TotalBRAM = #sum { BRAM : selected_realtime(C, L), bram(L, base, BRAM) }.

total_base_bram(BaseBRAMs) :-
    SecurityBaseBRAMs = #sum { BRAM, C : security_base_bram_for_component(C, BRAM) },
    RealtimeBaseBRAMs = #sum { BRAM, C : realtime_base_bram_for_component(C, BRAM) },
    BaseBRAMs = SecurityBaseBRAMs + RealtimeBaseBRAMs.

total_asset_bram(0).

total_bram_used(TotalUsedBRAM) :-
    total_asset_bram(TotalAssetBRAM),
    total_component_bram(ComponentBRAM),
    total_base_bram(BaseBRAMs),
    TotalUsedBRAM = TotalAssetBRAM + ComponentBRAM + BaseBRAMs.

#show total_bram_used/1.

:- total_bram_used(TotalUsedBRAM),
   system_capability(max_bram, MaxBRAM),
   TotalUsedBRAM > MaxBRAM.
