%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% ZERO-TRUST SOC – FULLY WORKING VERSION (Nov 2025)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1. SOC STRUCTURE
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

ip(aes). ip(npu).

master(cpu). master(dma).

domain(cpu, high).  domain(aes, high).
domain(dma, low).   domain(npu, low).

critical(aes).
safety_critical(npu).

% Interconnect
link(cpu, noc0).   link(noc0, aes).   link(noc0, npu).
link(dma, noc1).   link(noc1, npu).   link(noc1, aes).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 2. REACHABILITY
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

reachable(X,Y) :- link(X,Y).
reachable(X,Y) :- reachable(X,Z), link(Z,Y).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 3. CANDIDATE LOCATIONS AND CHOICE RULES
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

cand_fw(aes_in). cand_fw(npu_in).
cand_ps(se0).    cand_ps(se1).

% We MAY place a firewall at each candidate location
{ place_fw(FWL) : cand_fw(FWL) }.

% at least ONE policy server (this is the line that was wrong before)
1 { place_ps(PS) : cand_ps(PS) } .

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 4. ON-PATH MAPPING (which firewall protects which flow)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

on_path(aes_in, cpu, aes).
on_path(aes_in, dma, aes).
on_path(npu_in, cpu, npu).
on_path(npu_in, dma, npu).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 5. ZERO-TRUST PROTECTION FOR CRITICAL ASSETS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

protected(M,A) :- place_fw(FWL), on_path(FWL, M, A).

% Low-domain masters must be firewalled before reaching critical assets
:- master(M), domain(M,low), critical(A), reachable(M,A), not protected(M,A).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 6. RUNTIME MODES & SAFETY-CRITICAL ISOLATION (safe version)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

mode(normal). mode(attack_suspected). mode(attack_confirmed).

% In attack modes, deny EVERY master to the NPU
deny(M, npu, attack_suspected) :- master(M).
deny(M, npu, attack_confirmed) :- master(M).

% Can a low-domain master still reach IP in mode S?
reachable_low(IP, S) :-
    mode(S),
    master(M), domain(M,low),
    reachable(M, IP),
    not deny(M, IP, S).

% NPU is isolated in mode S if no low master can reach it
isolated(npu, S) :- mode(S), not reachable_low(npu, S).

% Safety requirement: NPU must be isolatable in at least one mode
:- safety_critical(npu), not isolated(npu, _).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 7. POLICY SERVER GOVERNANCE
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

ip_loc(aes, aes_in).
ip_loc(npu, npu_in).

governs(se0, aes_in).
governs(se0, npu_in).   % se0 can govern both firewalls
governs(se1, npu_in).

governs_ip(PS, IP) :-
    place_ps(PS),
    place_fw(FWL),
    ip_loc(IP, FWL),
    governs(PS, FWL).

% Every placed firewall must be governed by some policy server
:- place_fw(FWL), ip_loc(IP, FWL), not governs_ip(_, IP).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 8. EXPLICIT ALLOW RULES (normal mode only)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

allow(cpu, aes, normal).

final_allow(M,IP,S) :- allow(M,IP,S), not deny(M,IP,S).
final_deny(M,IP,S)  :- deny(M,IP,S).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 9. COST MODEL & OPTIMIZATION
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

fw_cost(aes_in,100). fw_cost(npu_in,120).
ps_cost(se0,200).    ps_cost(se1,180).

total_cost(C) :- C = #sum { Cost,FW  : place_fw(FW),  fw_cost(FW,Cost);
                            CostPS,PS : place_ps(PS), ps_cost(PS,CostPS) }.

#minimize { C : total_cost(C) }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 10. OUTPUT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#show place_fw/1.
#show place_ps/1.
#show final_allow/3.
#show final_deny/3.
#show total_cost/1.