%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% File: Target System Instantiation OT-1 (Full Resources)
% Last Edited: 4/3/2026
% Purpose: Define the Xilinx Kintex-7 410T target device
%          capabilities for the OpenTitan Earl Grey benchmark.
%          Full resources — nominal constraints.
% Reference: Kintex-7 XC7K410T datasheet
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define Kintex-7 410T system capabilities

system_capability(max_power, 15000).          % 15W * 100 (integer encoding)
system_capability(max_luts, 254200).          % XC7K410T: 254,200 LUTs
system_capability(max_ffs, 508400).           % XC7K410T: 508,400 FFs
system_capability(max_dsps, 1540).            % XC7K410T: 1,540 DSP48E1
system_capability(max_lutram, 63550).         % XC7K410T: 63,550 distributed RAM
system_capability(max_bufgs, 32).             % XC7K410T: 32 BUFGs
system_capability(max_bufg, 32).              % alias for opt_resource_enc.lp
system_capability(max_bram, 795).             % XC7K410T: 795 Block RAM (36Kb)

% Define User or System Constraints

system_capability(max_asset_risk, 200).  % raised from 100: MAC(V=30)+ZTL(L=5) on impact-10 components gives risk=150
