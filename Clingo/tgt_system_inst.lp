%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Target System Instantiation
% Last Edited: 6/24/2025
% Purpose: Define the target device's maximum power and	
%			resource capabilities
% Missing: 
%		- PYNQ-Z2's max DSP, LUTRAM, and BUFGs
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define PYNQ-Z2 system capabilities
 
system_capability(max_power, 15000).          % ASP/Potassco cannot handle decimal points. 15Watts (5V*3A) * 100. All power outputs should be d
system_capability(max_luts, 53200).           % Maximum number of LUTs allowed
system_capability(max_ffs, 106400).           % Maximum number of FFs allowed
system_capability(max_dsps, 106400).          % Maximum number of FFs allowed
system_capability(max_lutram, 106400).        % Maximum number of FFs allowed
system_capability(max_bufgs, 106400).         % Maximum number of FFs allowed




