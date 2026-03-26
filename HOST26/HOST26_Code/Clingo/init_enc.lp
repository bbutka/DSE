%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Initialize DSE Encoding
% Last Edited: 6/24/2025
% Purpose: Initialize the DSE with required constraints
%			Specifically, allow only one feature per asset
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initialization -------------------------------------------

% Allow only one selected logging feature per asset
1 { selected_logging(C, L) : logging_feature(L) } 1 :- asset(C, _,_).
% Allow only one selected security feature per asset
1 { selected_security(C, F) : security_feature(F) } 1 :- asset(C, _,_).

#show selected_logging/2.
#show selected_security/2.

% End Initialization ---------------------------------------
