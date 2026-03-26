%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Test Case 2
% Last Edited: 6/26/2025
% Purpose: Define a system with one component, eight assets
%			and the read/write impacts of each asset
%			Opposite testCase2 (eight components each with one asset)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Define components
component(c1,c2).

% Define assets
asset(c1, c1r1, read).
asset(c1, c1r1, write).

asset(c1, c1r2, read).
asset(c1, c1r2, write).

asset(c1, c1r3, read).
asset(c1, c1r3, write).

asset(c1, c1r4, read).
asset(c1, c1r4, write).

asset(c1, c1r5, read).
asset(c1, c1r5, write).

asset(c1, c1r6, read).
asset(c1, c1r6, write).

asset(c1, c1r7, read).
asset(c1, c1r7, write).

asset(c1, c1r8, read).
asset(c1, c1r8, write).

% Define assets
asset(c2, c2r1, read).
asset(c2, c2r1, write).

asset(c2, c2r2, read).
asset(c2, c2r2, write).

asset(c2, c2r3, read).
asset(c2, c2r3, write).

asset(c2, c2r4, read).
asset(c2, c2r4, write).

asset(c2, c2r5, read).
asset(c2, c2r5, write).

asset(c2, c2r6, read).
asset(c2, c2r6, write).

asset(c2, c2r7, read).
asset(c2, c2r7, write).

asset(c2, c2r8, read).
asset(c2, c2r8, write).

% Define impact of each asset

impact(c1r1, read, 1).
impact(c1r1, write, 5).

impact(c1r2, read, 5).
impact(c1r2, write, 2).

impact(c1r3, read, 3).
impact(c1r3, write, 3).

impact(c1r4, read, 3).
impact(c1r4, write, 4).

impact(c1r5, read, 4).
impact(c1r5, write, 1).

impact(c1r6, read, 5).
impact(c1r6, write, 3).

impact(c1r7, read, 1).
impact(c1r7, write, 2).

impact(c1r8, read, 2).
impact(c1r8, write, 4).

impact(c2r1, read, 1).
impact(c2r1, write, 5).

impact(c2r2, read, 5).
impact(c2r2, write, 2).

impact(c2r3, read, 3).
impact(c2r3, write, 3).

impact(c2r4, read, 3).
impact(c2r4, write, 4).

impact(c2r5, read, 4).
impact(c2r5, write, 1).

impact(c2r6, read, 5).
impact(c2r6, write, 3).

impact(c2r7, read, 1).
impact(c2r7, write, 2).

impact(c2r8, read, 2).
impact(c2r8, write, 4).

% Define the allowable latency for each asset read and write - set to 1000 if it does not matter what the latency is

allowable_latency(c1r1, read, 10).
allowable_latency(c1r1, write, 1000).

allowable_latency(c1r2, read, 1000).
allowable_latency(c1r2, write, 10).

allowable_latency(c1r3, read, 7).
allowable_latency(c1r3, write, 22).

allowable_latency(c1r4, read, 22).
allowable_latency(c1r4, write, 7).

allowable_latency(c1r5, read, 25).
allowable_latency(c1r5, write, 22).

allowable_latency(c1r6, read, 22).
allowable_latency(c1r6, write, 25).

allowable_latency(c1r7, read, 1000).
allowable_latency(c1r7, write, 1000).

allowable_latency(c1r8, read, 5).
allowable_latency(c1r8, write, 15).

allowable_latency(c2r1, read, 10).
allowable_latency(c2r1, write, 1000).

allowable_latency(c2r2, read, 1000).
allowable_latency(c2r2, write, 10).

allowable_latency(c2r3, read, 7).
allowable_latency(c2r3, write, 22).

allowable_latency(c2r4, read, 22).
allowable_latency(c2r4, write, 7).

allowable_latency(c2r5, read, 25).
allowable_latency(c2r5, write, 22).

allowable_latency(c2r6, read, 22).
allowable_latency(c2r6, write, 25).

allowable_latency(c2r7, read, 1000).
allowable_latency(c2r7, write, 1000).

allowable_latency(c2r8, read, 5).
allowable_latency(c2r8, write, 15).