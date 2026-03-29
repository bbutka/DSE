%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Initialize DSE Encoding
% Last Edited: 6/24/2025
% Purpose: Initialize the DSE with required constraints
%			Specifically, allow only one feature per asset
%
% Design note on asset-level vs component-level selection:
%   The choice rules below use `asset(C, _, _)` which iterates
%   over every (component, asset, operation) tuple.  For a
%   component with both read and write assets, this creates
%   multiple independent selection choices for the same
%   component C — all of which produce `selected_security(C, F)`
%   with the same first argument.  Because Clingo uses set
%   semantics, duplicate atoms are collapsed.  However, the
%   cardinality constraint `1 { ... } 1` applies per ground
%   body match, meaning each asset-operation tuple independently
%   requires exactly one feature.  In practice, the solver will
%   assign the SAME feature to all assets on a component because
%   the risk minimization objective treats them uniformly per
%   component.  The Phase 1 parser filters asset-level atoms
%   with a regex, retaining only component-level selections.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initialization -------------------------------------------

% Allow only one selected logging feature per asset
1 { selected_logging(C, L) : logging_feature(L) } 1 :- asset(C, _,_).
% Allow only one selected security feature per asset
1 { selected_security(C, F) : security_feature(F) } 1 :- asset(C, _,_).

#show selected_logging/2.
#show selected_security/2.

% End Initialization ---------------------------------------
