%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Test Case 2
% Last Edited: 6/26/2025
% Purpose: Define a system with eight components, one asset
%			per component and the read/write impacts of each asset
%           Edit: Added necessary functions for redundancy and
%           reachability.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define components
component(c1; c2; c3).

% Define assets
asset(c1, c1r1, read).
asset(c1, c1r1, write).

asset(c2, c2r1, read).
asset(c2, c2r1, write).

asset(c3, c3r1, read).
asset(c3, c3r1, write).

% Define redundant components

redundant_group(1, c1).
redundant_group(1, c2).
redundant_group(1, c3).

% Define impact of each asset

impact(c1r1, read, 1).
impact(c1r1, write, 5).

impact(c2r1, read, 5).
impact(c2r1, write, 2).

impact(c3r1, read, 3).
impact(c3r1, write, 3).


% Define the allowable latency for each asset read and write - set to 1000 if it does not matter what the latency is

allowable_latency(c1r1, read, 10).
allowable_latency(c1r1, write, 1000).

allowable_latency(c2r1, read, 1000).
allowable_latency(c2r1, write, 10).

allowable_latency(c3r1, read, 7).
allowable_latency(c3r1, write, 22).

