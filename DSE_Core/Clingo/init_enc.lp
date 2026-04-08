%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: [Author]
% File: Initialize DSE Encoding
% Last Edited: 4/8/2026
% Purpose: Initialize the DSE with required constraints
%          Specifically, allow only one feature per receiver/component
%
% Design note:
%   Phase 1 features are selected once per receiver/component.
%   Resource accounting, risk scoring, and the Python backends are all
%   component-scoped, so grounding the choice over asset(C,_,_) only
%   duplicates equivalent decisions and inflates the TC9 ground program.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initialization -------------------------------------------

% Allow only one selected realtime-detection feature per receiver/component
1 { selected_realtime(C, L) : realtime_feature(L) } 1 :- receiver(C).
% Allow only one selected security feature per receiver/component
1 { selected_security(C, F) : security_feature(F) } 1 :- receiver(C).

#show selected_realtime/2.
#show selected_security/2.

% End Initialization ---------------------------------------
