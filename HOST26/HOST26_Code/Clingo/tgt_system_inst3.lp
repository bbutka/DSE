%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Target System Instantiation 1
% Last Edited: 6/25/2025
% Purpose: Define the target device's maximum power and	
%			resource capabilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define PYNQ-Z2 system capabilities
 
system_capability(max_power, 1000).          % ASP/Potassco cannot handle decimal points. 15Watts (5V*3A) * 100
system_capability(max_luts, 53200).           % Maximum number of LUTs allowed
system_capability(max_ffs, 106400).           % Maximum number of FFs allowed
system_capability(max_dsps, 220).          % Maximum number of DSPs allowed - real value 220
system_capability(max_lutram, 17400).        % Maximum number of LUTRAM allowed - real value 17400
system_capability(max_bufgs, 32).         % Maximum number of BUFGs allowed - real value 32
system_capability(max_bram, 140).          % Maximum number of BRAM allowed - real value 140

% Define User or System Constraints

system_capability(max_asset_risk, 100).


