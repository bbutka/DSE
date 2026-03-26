%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Initialize DSE Encoding
% Last Edited: 6/24/2025
% Purpose: Initialize the DSE with required constraints
%			Specifically, allow only one feature per asset
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initialization -------------------------------------------

% Allow only one selected logging feature per asset
1 { selected_logging(A, L) : logging_feature(L) } 1 :- asset(_, A).
% Allow only one selected security feature per asset
1 { selected_security(A, F) : security_feature(F) } 1 :- asset(_, A).

#show selected_logging/2.
#show selected_security/2.

% End Initialization ---------------------------------------
