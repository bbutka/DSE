% Define components
component(p1; c1; c2).

% Define assets
asset(p1, p1r1).
asset(c1, c1r1).
asset(c2, c2r1).

% Define impact of each asset
impact(p1r1, read , 1).
impact(p1r1, write , 5).

impact(c1r1, read , 3).
impact(c1r1, write , 4).

impact(c2r1, read , 3).
impact(c2r1, write , 2).

