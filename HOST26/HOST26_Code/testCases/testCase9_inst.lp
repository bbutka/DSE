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
component(c1; c2; c3; c4; c5; c6; c7; c8).

% Define assets
asset(c1, c1r1, read).
asset(c1, c1r1, write).

asset(c2, c2r1, read).
asset(c2, c2r1, write).

asset(c3, c3r1, read).
asset(c3, c3r1, write).

asset(c4, c4r1, read).
asset(c4, c4r1, write).

asset(c5, c5r1, read).
asset(c5, c5r1, write).

asset(c6, c6r1, read).
asset(c6, c6r1, write).

asset(c7, c7r1, read).
asset(c7, c7r1, write).

asset(c8, c8r1, read).
asset(c8, c8r1, write).

% Define redundant components

redundant_group(1, c1).
redundant_group(1, c2).
redundant_group(1, c3).
redundant_group(1, c4).
redundant_group(1, c5).
redundant_group(1, c5).

% Define impact of each asset

impact(c1r1, read, 1).
impact(c1r1, write, 5).

impact(c2r1, read, 5).
impact(c2r1, write, 2).

impact(c3r1, read, 3).
impact(c3r1, write, 3).

impact(c4r1, read, 3).
impact(c4r1, write, 4).

impact(c5r1, read, 4).
impact(c5r1, write, 1).

impact(c6r1, read, 5).
impact(c6r1, write, 3).

impact(c7r1, read, 1).
impact(c7r1, write, 2).

impact(c8r1, read, 2).
impact(c8r1, write, 4).

% Define the allowable latency for each asset read and write - set to 1000 if it does not matter what the latency is

allowable_latency(c1r1, read, 10).
allowable_latency(c1r1, write, 1000).

allowable_latency(c2r1, read, 1000).
allowable_latency(c2r1, write, 10).

allowable_latency(c3r1, read, 7).
allowable_latency(c3r1, write, 22).

allowable_latency(c4r1, read, 22).
allowable_latency(c4r1, write, 7).

allowable_latency(c5r1, read, 25).
allowable_latency(c5r1, write, 22).

allowable_latency(c6r1, read, 22).
allowable_latency(c6r1, write, 25).

allowable_latency(c7r1, read, 1000).
allowable_latency(c7r1, write, 1000).

allowable_latency(c8r1, read, 5).
allowable_latency(c8r1, write, 15).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% ZTA TOPOLOGY — added for zero-trust integration
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Initiators (bus masters)
master(sys_cpu). master(dma).

% Target IPs (receivers)
receiver(c1). receiver(c2). receiver(c3). receiver(c4).
receiver(c5). receiver(c6). receiver(c7). receiver(c8).

% Interconnect buses
bus(noc0). bus(noc1).

% Topology links
% sys_cpu and dma both drive noc0 → redundancy group (c1-c5)
link(sys_cpu, noc0).
link(dma,     noc0).
link(noc0, c1). link(noc0, c2). link(noc0, c3).
link(noc0, c4). link(noc0, c5).

% dma also drives noc1 → standalone IPs (c6-c8)
link(dma,  noc1).
link(noc1, c6). link(noc1, c7). link(noc1, c8).

% Trust domains: low = less trusted initiator; high = protected IP
domain(sys_cpu, low).  domain(dma, low).
domain(c1, high). domain(c2, high). domain(c3, high).
domain(c4, high). domain(c5, high).
domain(c6, high). domain(c7, low).  domain(c8, high).

% Critical IPs (low-domain masters must be firewalled before these)
critical(c1). critical(c2). critical(c3).
critical(c4). critical(c5). critical(c6). critical(c8).

% c8 is safety-critical: must be fully isolatable in attack_confirmed mode
safety_critical(c8).

% ZTA candidate firewall locations
cand_fw(pep_group).      % guards noc0 path (c1-c5)
cand_fw(pep_standalone). % guards noc1 path (c6-c8)

% Candidate policy servers
cand_ps(ps0). cand_ps(ps1).

% On-path facts: on_path(FWLocation, Master, IP)
on_path(pep_group,      sys_cpu, C) :- receiver(C), link(noc0, C).
on_path(pep_group,      dma,     C) :- receiver(C), link(noc0, C).
on_path(pep_standalone, dma,     C) :- receiver(C), link(noc1, C).

% Which firewall location guards which IP
ip_loc(C, pep_group)      :- receiver(C), link(noc0, C).
ip_loc(C, pep_standalone) :- receiver(C), link(noc1, C).

% Policy server governance
governs(ps0, pep_group). governs(ps0, pep_standalone).
governs(ps1, pep_group).

% Hardware costs
fw_cost(pep_group,      150).
fw_cost(pep_standalone, 100).
ps_cost(ps0, 200).
ps_cost(ps1, 180).

% Alias for opt_resource_enc.lp which uses max_bufg (tgt_system_inst uses max_bufgs)
system_capability(max_bufg, 32).

% Explicit allow rules in normal mode
allow(sys_cpu, C, normal) :- receiver(C), link(noc0, C).
allow(dma,     C, normal) :- receiver(C), link(noc0, C).
allow(dma,     C, normal) :- receiver(C), link(noc1, C).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% LEAST-PRIVILEGE ACCESS NEEDS
%% What each master *actually* requires (ground truth).
%% Anything granted beyond this is excess privilege.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% sys_cpu (processor): r+w to compute group, read-only to monitor (c6)
% Does NOT need access to c7 (low-value log sink) or c8 (hw timer/IO)
access_need(sys_cpu, c1, read).  access_need(sys_cpu, c1, write).
access_need(sys_cpu, c2, read).  access_need(sys_cpu, c2, write).
access_need(sys_cpu, c3, read).  access_need(sys_cpu, c3, write).
access_need(sys_cpu, c4, read).  access_need(sys_cpu, c4, write).
access_need(sys_cpu, c5, read).  access_need(sys_cpu, c5, write).
access_need(sys_cpu, c6, read).  % status monitoring only

% dma (data mover): write-only to compute group, read from c8 (acquisition)
% Does NOT need write to c8 (read acquisition only), no access to c7
access_need(dma, c1, write). access_need(dma, c2, write).
access_need(dma, c3, write). access_need(dma, c4, write).
access_need(dma, c5, write).
access_need(dma, c6, write).   % bulk data write to monitor store
access_need(dma, c8, read).    % data acquisition read


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% SUBJECT ROLES
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

role(sys_cpu, processor).
role(dma,     data_mover).

% Role-level access needs (may be more permissive than per-subject needs;
% per-subject access_need above takes precedence for least-privilege checks)
role_need(processor,  C, read)  :- receiver(C), domain(C, high).
role_need(processor,  C, write) :- receiver(C), link(noc0, C).
role_need(data_mover, C, write) :- receiver(C).
role_need(data_mover, c8, read).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% MISSION CONTEXT
%% Three operational phases with different access requirements.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Phases are mutually exclusive at runtime; all declared here for analysis.
mission_phase(operational).
mission_phase(maintenance).
mission_phase(emergency).

% Operational: full normal access as per access_need
mission_access(M, C, Op, operational) :- access_need(M, C, Op).

% Maintenance: sys_cpu gets r+w to ALL components (firmware update etc.)
% dma access unchanged
mission_access(sys_cpu, C, read,  maintenance) :- receiver(C).
mission_access(sys_cpu, C, write, maintenance) :- receiver(C).
mission_access(dma,     C, Op,    maintenance) :- access_need(dma, C, Op).

% Emergency: read-only for all masters (prevent state corruption under duress)
mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).

% Policy exception: temporary maintenance write grant for dma to c7
% (normally dma has no access to c7; this models a one-time exception)
policy_exception(dma, c7, write, maintenance, reason(firmware_update)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% TRUST ANCHORS AND ATTESTATION
%% Documents what establishes trust in each component/master.
%% Gaps are security findings, not UNSAT conditions.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Hardware root of trust (immutable boot ROM / eFuse)
hardware_rot(c1). hardware_rot(c2).
% c3-c8 lack hardware RoT (cost-reduced IPs)

% Secure boot (firmware signature verified at boot)
secure_boot(c1). secure_boot(c2). secure_boot(c3).
secure_boot(c4). secure_boot(c5).
% c6, c7, c8 lack secure boot (standalone peripherals)

% Platform attestation (TPM/remote attestation capable)
attested(sys_cpu).  % CPU has TPM
% dma is a simple DMA engine — no attestation
% IPs do not self-attest (they are attested via platform attestation)

% Signed policy enforcement
signed_policy(ps0).   % ps0 enforces cryptographically signed policy
% ps1 does not use signed policies (secondary, lower assurance)

% Key storage (encrypted key material)
key_storage(c1). key_storage(c2).   % secure enclaves

% Integrity of telemetry
trusted_telemetry(sys_cpu). trusted_telemetry(c1). trusted_telemetry(c2).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% SERVICES
%% Which components contribute to each named service.
%% quorum = minimum live members required.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

service_component(compute_svc, c1).
service_component(compute_svc, c2).
service_component(compute_svc, c3).
service_component(compute_svc, c4).
service_component(compute_svc, c5).
service_quorum(compute_svc, 3).  % need 3-of-5 (majority) to continue

service_component(monitor_svc, c6).
service_quorum(monitor_svc, 1).  % SPOF — only one monitor node

service_component(io_svc, c8).
service_quorum(io_svc, 1).       % SPOF — c8 is the sole IO path


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% CONTROL PLANE COMPONENTS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

policy_server(ps0). policy_server(ps1).
policy_enforcement_point(pep_group). policy_enforcement_point(pep_standalone).

% Which PEP guards which IPs (for control-plane compromise analysis)
pep_guards(pep_group,      C) :- receiver(C), link(noc0, C).
pep_guards(pep_standalone, C) :- receiver(C), link(noc1, C).

% Which PS governs which PEP (for PS compromise blast radius)
% governs/2 already defined above; this makes it queryable in resilience enc
ps_governs_pep(ps0, pep_group). ps_governs_pep(ps0, pep_standalone).
ps_governs_pep(ps1, pep_group).