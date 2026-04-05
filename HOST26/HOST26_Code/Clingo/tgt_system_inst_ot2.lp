%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% File: Target System Instantiation OT-2 (Constrained LUTs)
% Last Edited: 4/3/2026
% Purpose: Define the Xilinx Kintex-7 410T target device
%          with restricted LUT budget for the OpenTitan
%          Earl Grey benchmark. Simulates partial FPGA usage.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define Kintex-7 410T system capabilities (LUT-constrained)

system_capability(max_power, 15000).          % 15W * 100 (integer encoding)
system_capability(max_luts, 25000).           % Restricted: ~10% of XC7K410T
system_capability(max_ffs, 508400).           % XC7K410T: 508,400 FFs
system_capability(max_dsps, 1540).            % XC7K410T: 1,540 DSP48E1
system_capability(max_lutram, 63550).         % XC7K410T: 63,550 distributed RAM
system_capability(max_bufgs, 32).             % XC7K410T: 32 BUFGs
system_capability(max_bufg, 32).              % alias for opt_resource_enc.lp
system_capability(max_bram, 795).             % XC7K410T: 795 Block RAM (36Kb)

% Define User or System Constraints

system_capability(max_asset_risk, 500).
