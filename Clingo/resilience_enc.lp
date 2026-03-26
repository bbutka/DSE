%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% File: Clingo/resilience_enc.lp
% Purpose: Scenario-based resilience evaluation.
%          Loaded in Phase 2 only (not during optimization).
%          Requires topology_enc.lp to be loaded first.
%
% Scenario inputs (injected as facts by Python per scenario):
%   compromised(Node) - attacker has execution on this node
%   failed(Node)      - node is unavailable (fault/DoS)
%   selected_security(Asset, Feature) - from Phase 1 optimal
%   selected_logging(Asset, Feature)  - from Phase 1 optimal
%   register_risk_fact(Asset, Risk)   - from Phase 1 optimal
%
% Amplification factors (integers, real value = factor / 10):
%   Direct compromise:             30  (3.0x baseline risk)
%   Indirect via cross-zone link:  20  (2.0x baseline risk)
%   Indirect via same-zone link:   15  (1.5x baseline risk)
%   No exposure (baseline):        10  (1.0x baseline risk)
%
% Stratification: all NAF is over ground facts (stratum 0).
%   See inline comments for per-predicate strata.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% ============================================================
% SECTION 1: Compromise exposure classification
% ============================================================

% direct_exposure(Asset, SourceNode, Factor):
%   compromised(SourceNode) and SourceNode directly owns Asset.
%   Factor 30 = attacker fully bypasses asset's security feature.
%   Stratum 1 (positive over compromised/1 facts).
direct_exposure(A, N, 30) :-
    compromised(N),
    asset(N, A).

% indirect_exposure_cross_zone(Asset, SourceNode, Factor):
%   Attacker at SourceNode can reach Asset's owner via active
%   topology AND the path crosses a trust zone boundary.
%   Factor 20: cross-zone traversal undermines domain isolation.
%   Stratum 3 (over asset_reachable/2 which is stratum 3).
indirect_exposure_cross_zone(A, N, 20) :-
    compromised(N),
    node_zone(N, ZN),
    asset_reachable(N, A),
    asset(Owner, A),
    node_zone(Owner, ZOwner),
    ZN != ZOwner.

% indirect_exposure_same_zone(Asset, SourceNode, Factor):
%   Attacker at SourceNode can reach Asset's owner via active
%   topology within the same trust zone.
%   Factor 15: lateral movement within a zone.
%   Stratum 3.
indirect_exposure_same_zone(A, N, 15) :-
    compromised(N),
    node_zone(N, ZN),
    asset_reachable(N, A),
    asset(Owner, A),
    node_zone(Owner, ZOwner),
    ZN = ZOwner.


% ============================================================
% SECTION 2: Per-asset scenario risk
% Scenario risk = BaseRisk * MaxAmplificationFactor
% We take the MAXIMUM applicable factor per asset to avoid
% double-counting when multiple compromised nodes can reach
% the same asset (e.g. jtag + periph0 both reach flash).
% ============================================================

% max_amp_factor(Asset, Factor):
%   Maximum amplification factor applicable to this asset under
%   the current scenario. Sentinel "10 : asset(_, A)" ensures
%   the aggregate set is never empty (defaults to 1.0x).
%   Stratum 4 (aggregate over strata 1-3).
max_amp_factor(A, Factor) :-
    asset(_, A),
    Factor = #max { F : direct_exposure(A, _, F) ;
                    F : indirect_exposure_cross_zone(A, _, F) ;
                    F : indirect_exposure_same_zone(A, _, F) ;
                    10 : asset(_, A) }.

% scenario_asset_risk(Asset, ScenRisk):
%   ScenRisk = BaseRisk * Factor  (integer; divide by 10 in Python)
%   Stratum 5.
scenario_asset_risk(A, ScenRisk) :-
    register_risk_fact(A, BaseRisk),
    max_amp_factor(A, Factor),
    ScenRisk = BaseRisk * Factor.

#show scenario_asset_risk/2.

% scenario_total_risk(Total): sum of all per-asset scenario risks.
scenario_total_risk(Total) :-
    Total = #sum { R, A : scenario_asset_risk(A, R) }.

#show scenario_total_risk/1.


% ============================================================
% SECTION 3: Blast radius under current compromise scenario
% ============================================================

% scenario_blast_radius(CompromisedNode, ReachableNodeCount):
%   For each compromised node, report how many other nodes
%   (not just assets) it can reach using full topology.
%   Uses blast_radius/2 from topology_enc.lp.
scenario_blast_radius(N, R) :-
    compromised(N),
    blast_radius(N, R).

#show scenario_blast_radius/2.


% ============================================================
% SECTION 4: Asset availability under failure scenarios
% ============================================================

% An asset is unavailable if:
%   (a) its owner node has directly failed, OR
%   (b) its owner is isolated: every path to it passes through
%       at least one failed node (checked via active_reachable).
%
% non_failed_can_reach_owner(Asset):
%   There exists at least one non-failed component N (other
%   than the owner itself) that can actively reach the owner.
%   Stratum 3 (NAF over failed/1 facts; positive over active_reachable).
non_failed_can_reach_owner(A) :-
    asset(Owner, A),
    component(N),
    not failed(N),
    N != Owner,
    active_reachable(N, Owner).

% isolated_asset(Asset):
%   Owner is not itself failed, but no non-failed node can reach it.
%   Stratum 4 (NAF over non_failed_can_reach_owner at stratum 3).
isolated_asset(A) :-
    asset(Owner, A),
    not failed(Owner),
    not non_failed_can_reach_owner(A).

% asset_unavailable(Asset): directly failed or isolated.
%   Stratum 5.
asset_unavailable(A) :-
    failed(N),
    asset(N, A).

asset_unavailable(A) :- isolated_asset(A).

% asset_available(Asset): complement of unavailable.
%   Stratum 6 (NAF over asset_unavailable at stratum 5).
asset_available(A) :-
    asset(_, A),
    not asset_unavailable(A).

#show asset_unavailable/1.
#show asset_available/1.


% ============================================================
% SECTION 5: Critical asset loss detection
% ============================================================

% critical_asset_unavailable(Asset):
%   Asset has high impact (>= 6) AND is unavailable.
%   These represent the most severe failure consequences.
critical_asset_unavailable(A) :-
    asset_unavailable(A),
    impact(A, I),
    I >= 6.

#show critical_asset_unavailable/1.


% ============================================================
% SECTION 6: Compromise path annotation
% ============================================================

% compromise_path_exists(EntryPoint, Asset):
%   An external entry point can reach Asset via full topology
%   (not accounting for failures - shows worst-case exposure).
%   Used to identify which external-zone nodes threaten
%   which assets regardless of current scenario.
compromise_path_exists(Entry, A) :-
    external_entry_point(Entry),
    asset_reachable(Entry, A).

compromise_path_exists(Entry, A) :-
    external_entry_point(Entry),
    asset_owned(Entry, A).

#show compromise_path_exists/2.
