%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Test Case 1
% Last Edited: 6/26/2025
% Purpose: Define a system with three components, three assets
%			and the read/write impacts of each asset
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define components
component(p1; c1; c2).

% Define assets
asset(p1, p1r1, read).
asset(p1, p1r1, write).

asset(c1, c1r1, read).
asset(c1, c1r1, write).

asset(c2, c2r1, read).
asset(c2, c2r1, write).


% Define impact of each asset
impact(p1r1, read, 1).
impact(p1r1, write, 5).

impact(c1r1, read, 3).
impact(c1r1, write, 4).

impact(c2r1, read, 3).
impact(c2r1, write, 2).


% Define the allowable latency for each asset read and write - set to 1000 if it does not matter what the latency is
allowable_latency(p1r1, read, 1000).
allowable_latency(p1r1, write, 15).

allowable_latency(c1r1, read, 10).
allowable_latency(c1r1, write, 1000).

allowable_latency(c2r1, read, 1000).
allowable_latency(c2r1, write, 22).
