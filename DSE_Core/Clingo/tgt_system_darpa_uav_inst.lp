%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_darpa_uav_inst.lp
%% Target: PYNQ-Z2 (Zynq-7000, xc7z020clg400-1)
%%
%% DARPA CASE UAV Surveillance System
%% ===================================
%% Translation of the DARPA Cyber Assured Systems Engineering (CASE)
%% UAV surveillance architecture from its AADL software representation
%% (santoslab/case-uav-phase2) into an SoC interconnect model.
%%
%% The original system deploys software threads on a Jetson TK1
%% mission computer with seL4 separation kernel.  This translation
%% models a hardware-consolidated implementation where safety and
%% security functions are realized as dedicated IP cores on a
%% shared FPGA fabric, reflecting the avionics trend toward
%% single-chip integrated avionics.
%%
%% Topology (15 components):
%%   3 masters  (mc — mission computer, fc — flight controller, gs — ground station)
%%   4 buses    (bus_rf, bus_mc, bus_uart, bus_wifi)
%%   9 IP cores (radio_drv, fpln, wpm, cam_mgr, wifi_drv, uart_drv,
%%               nfzdb, attest_gate, geofence, fpln_filt, swu)
%%   1 FW       (pep_mc)   — guards internal MC bus
%%   2 PSs      (ps_mc, ps_uart) — policy servers
%%
%% Phase 2 BriefCASE/Collins hardening components modeled:
%%   attest_gate  — attestation gate verifying GS identity
%%   fpln_filt    — CakeML-verified flight plan filter
%%   geofence     — geofence monitor checking no-fly zones
%%
%% DUAL-RISK BUDGET
%% ================
%% max_security_risk = 50 — multiplicative cap for high-impact non-redundant assets.
%%
%% max_avail_risk = 25 — no redundancy groups (all SPOF), so unused.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% ── FPGA resource budget (PYNQ-Z2 xc7z020) ──────────────────────────────
system_capability(max_power,  15000).   % 15W
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).
system_capability(max_attack_depth, 6).

% ── Dual-risk budget caps ────────────────────────────────────────────────
system_capability(max_security_risk, 50).  % multiplicative cap
system_capability(max_avail_risk,   25).   % probabilistic cap (no groups)

% ── Masters ──────────────────────────────────────────────────────────────
master(mc).        % Mission Computer (ARM processor running seL4)
master(fc).        % Flight Controller (real-time ARM Cortex-M)
master(gs).        % Ground Station radio (external, untrusted)

% ── Receiver components ─────────────────────────────────────────────────
component(radio_drv).      % Radio driver (bridges RF to MC bus)
component(fpln).           % Flight Planner
component(wpm).            % Waypoint Manager
component(cam_mgr).        % Camera Manager
component(wifi_drv).       % WiFi driver (maintenance link)
component(uart_drv).       % UART driver (MC ↔ FC serial link)
component(nfzdb).          % No-Fly Zone Database
component(attest_gate).    % Attestation Gate (CakeML verified)
component(geofence).       % Geofence Monitor (CakeML verified)
component(fpln_filt).      % Flight Plan Filter (CakeML verified)
component(swu).            % Software Updater

receiver(radio_drv).
receiver(fpln).
receiver(wpm).
receiver(cam_mgr).
receiver(wifi_drv).
receiver(uart_drv).
receiver(nfzdb).
receiver(attest_gate).
receiver(geofence).
receiver(fpln_filt).
receiver(swu).

% ── Domains (6-level trust model) ──────────────────────────────────────
domain(mc,           privileged).  % seL4-verified, high trust
domain(fc,           privileged).  % safety-critical flight controller
domain(gs,           untrusted).   % external ground station
domain(radio_drv,    low).         % RF-facing, bridges untrusted data
domain(fpln,         normal).      % application-level thread
domain(wpm,          normal).      % application-level thread
domain(cam_mgr,      normal).      % camera data processing
domain(wifi_drv,     untrusted).   % WiFi maintenance interface
domain(uart_drv,     normal).      % serial driver, MC↔FC
domain(nfzdb,        high).        % geofence data integrity critical
domain(attest_gate,  root).        % CakeML-verified, highest trust
domain(geofence,     high).        % CakeML-verified safety monitor
domain(fpln_filt,    high).        % CakeML-verified safety filter
domain(swu,          privileged).  % firmware update, privileged access

% ── Exploitability (CVSS-style, 1=hard, 3=neutral, 5=trivial) ──────────
exploitability(mc,           2).   % seL4-hardened
exploitability(fc,           2).   % dedicated RT processor, limited attack surface
exploitability(gs,           4).   % external entity, partially controlled
exploitability(radio_drv,    5).   % RF interface, remotely exploitable
exploitability(fpln,         3).   % application thread
exploitability(wpm,          3).   % application thread
exploitability(cam_mgr,      3).   % camera processing
exploitability(wifi_drv,     5).   % WiFi interface, remotely exploitable
exploitability(uart_drv,     3).   % serial driver
exploitability(nfzdb,        2).   % read-mostly database
exploitability(attest_gate,  1).   % CakeML-verified, formally proven
exploitability(geofence,     1).   % CakeML-verified, formally proven
exploitability(fpln_filt,    1).   % CakeML-verified, formally proven
exploitability(swu,          4).   % firmware updater, attack target

% ── Assets and impacts (CIA triad) ──────────────────────────────────────

% radio_drv — RF bridge, bidirectional, high-value compromise target
asset(radio_drv, radio_drvr1, read).
asset(radio_drv, radio_drvr1, write).
asset(radio_drv, radio_drvr1, avail).
impact(radio_drvr1, read,  4).     % eavesdrop on commands
impact(radio_drvr1, write, 5).     % inject malicious commands
impact(radio_drvr1, avail, 4).     % loss of GS communication

% fpln — flight planner, bidirectional
asset(fpln, fplnr1, read).
asset(fpln, fplnr1, write).
asset(fpln, fplnr1, avail).
impact(fplnr1, read,  3).         % flight plan disclosure
impact(fplnr1, write, 5).         % flight plan manipulation
impact(fplnr1, avail, 4).         % loss of mission planning

% wpm — waypoint manager, bidirectional
asset(wpm, wpmr1, read).
asset(wpm, wpmr1, write).
asset(wpm, wpmr1, avail).
impact(wpmr1, read,  2).          % waypoint disclosure
impact(wpmr1, write, 5).          % waypoint manipulation → flight deviation
impact(wpmr1, avail, 5).          % loss of navigation

% cam_mgr — camera manager, output-heavy
asset(cam_mgr, cam_mgrr1, read).
asset(cam_mgr, cam_mgrr1, write).
impact(cam_mgrr1, read,  2).      % surveillance data disclosure
impact(cam_mgrr1, write, 3).      % camera config manipulation

% wifi_drv — WiFi maintenance, bidirectional, untrusted
asset(wifi_drv, wifi_drvr1, read).
asset(wifi_drv, wifi_drvr1, write).
asset(wifi_drv, wifi_drvr1, avail).
impact(wifi_drvr1, read,  3).     % maintenance data leak
impact(wifi_drvr1, write, 4).     % unauthorized firmware injection
impact(wifi_drvr1, avail, 2).     % maintenance link not safety-critical

% uart_drv — UART serial, bidirectional, on safety-critical path
asset(uart_drv, uart_drvr1, read).
asset(uart_drv, uart_drvr1, write).
asset(uart_drv, uart_drvr1, avail).
impact(uart_drvr1, read,  3).     % command interception
impact(uart_drvr1, write, 5).     % inject flight commands
impact(uart_drvr1, avail, 5).     % loss of MC↔FC link

% nfzdb — no-fly zone database, read-heavy, integrity-critical
asset(nfzdb, nfzdbr1, read).
asset(nfzdb, nfzdbr1, write).
asset(nfzdb, nfzdbr1, avail).
impact(nfzdbr1, read,  1).        % NFZ data low confidentiality
impact(nfzdbr1, write, 5).        % NFZ corruption → geofence failure
impact(nfzdbr1, avail, 4).        % NFZ unavailable → safety degraded

% attest_gate — attestation gate, input-only (verifies GS identity)
asset(attest_gate, attest_gater1, read).
asset(attest_gate, attest_gater1, avail).
impact(attest_gater1, read,  2).   % attestation result disclosure
impact(attest_gater1, avail, 5).   % loss of attestation → accept unsigned

% geofence — geofence monitor, bidirectional (reads NFZ, filters plans)
asset(geofence, geofencer1, read).
asset(geofence, geofencer1, write).
asset(geofence, geofencer1, avail).
impact(geofencer1, read,  2).     % geofence config disclosure
impact(geofencer1, write, 5).     % geofence bypass → fly into restricted
impact(geofencer1, avail, 5).     % geofence down → safety degraded

% fpln_filt — flight plan filter, bidirectional
asset(fpln_filt, fpln_filtr1, read).
asset(fpln_filt, fpln_filtr1, write).
asset(fpln_filt, fpln_filtr1, avail).
impact(fpln_filtr1, read,  2).    % filter config disclosure
impact(fpln_filtr1, write, 5).    % filter bypass → malicious plans pass
impact(fpln_filtr1, avail, 5).    % filter down → unfiltered flight plans

% swu — software updater, write-heavy, high-value
asset(swu, swur1, read).
asset(swu, swur1, write).
impact(swur1, read,  3).          % firmware disclosure
impact(swur1, write, 5).          % malicious firmware injection

% ── Latency constraints ─────────────────────────────────────────────────
allowable_latency(radio_drvr1,   read, 10).
allowable_latency(radio_drvr1,   write, 10).
allowable_latency(fplnr1,        read, 15).
allowable_latency(fplnr1,        write, 15).
allowable_latency(wpmr1,         read, 10).
allowable_latency(wpmr1,         write, 10).
allowable_latency(cam_mgrr1,     read, 1000).
allowable_latency(cam_mgrr1,     write, 1000).
allowable_latency(wifi_drvr1,    read, 1000).
allowable_latency(wifi_drvr1,    write, 1000).
allowable_latency(uart_drvr1,    read, 5).
allowable_latency(uart_drvr1,    write, 5).
allowable_latency(nfzdbr1,       read, 15).
allowable_latency(nfzdbr1,       write, 1000).
allowable_latency(attest_gater1, read, 8).
allowable_latency(geofencer1,    read, 10).
allowable_latency(geofencer1,    write, 10).
allowable_latency(fpln_filtr1,   read, 8).
allowable_latency(fpln_filtr1,   write, 8).
allowable_latency(swur1,         read, 1000).
allowable_latency(swur1,         write, 1000).

% ── Buses ────────────────────────────────────────────────────────────────
bus(bus_rf).       % GS ↔ radio_drv (RF link)
bus(bus_mc).       % Mission Computer internal (AXI/seL4 mediated)
bus(bus_uart).     % MC ↔ FC serial link
bus(bus_wifi).     % MC ↔ WiFi/Camera (maintenance/surveillance)

% ── Topology links ──────────────────────────────────────────────────────
% Ground station → RF bus → radio driver
link(gs,        bus_rf).
link(bus_rf,    radio_drv).

% Radio driver bridges RF into MC internal bus
link(radio_drv, bus_mc).

% MC internal bus: mission computer drives all internal threads
link(mc,        bus_mc).
link(bus_mc,    attest_gate).
link(bus_mc,    fpln).
link(bus_mc,    fpln_filt).
link(bus_mc,    geofence).
link(bus_mc,    wpm).
link(bus_mc,    cam_mgr).
link(bus_mc,    nfzdb).
link(bus_mc,    uart_drv).
link(bus_mc,    swu).

% MC → WiFi bus (maintenance/camera)
link(mc,        bus_wifi).
link(bus_wifi,  wifi_drv).
link(bus_wifi,  cam_mgr).

% UART bus: MC ↔ FC
link(uart_drv,  bus_uart).
link(bus_uart,  fc).
link(fc,        bus_uart).

% ── Critical IPs (low-trust masters must be firewalled) ─────────────────
critical(fpln).          % flight plan manipulation
critical(wpm).           % waypoint manipulation → flight deviation
critical(geofence).      % geofence bypass → fly into restricted
critical(fpln_filt).     % filter bypass → malicious plans pass
critical(nfzdb).         % NFZ corruption → geofence failure
critical(uart_drv).      % command injection into FC serial link
critical(attest_gate).   % attestation bypass
critical(swu).           % firmware injection

% ── Safety-critical components ──────────────────────────────────────────
safety_critical(fc).          % flight controller
safety_critical(geofence).    % geofence monitor
safety_critical(fpln_filt).   % verified flight plan filter
safety_critical(uart_drv).    % MC↔FC link integrity

% ── ZTA candidate firewalls ─────────────────────────────────────────────
cand_fw(pep_mc).         % guards MC internal bus from radio_drv bridge

% ── Candidate policy servers ────────────────────────────────────────────
cand_ps(ps_mc).          % MC-resident policy server
cand_ps(ps_uart).        % UART-side policy server (FC protection)

% ── On-path facts: on_path(FW, Master, IP) ──────────────────────────────
% pep_mc sits between radio_drv (bridging untrusted GS) and MC internals
on_path(pep_mc, gs, C) :- receiver(C), link(bus_mc, C).

% ── IP location behind firewalls ────────────────────────────────────────
ip_loc(C, pep_mc) :- receiver(C), link(bus_mc, C).

% ── Policy server governance ────────────────────────────────────────────
governs(ps_mc,   pep_mc).
governs(ps_uart,  pep_mc).   % backup governance

% ── Hardware costs ──────────────────────────────────────────────────────
fw_cost(pep_mc,    200).
ps_cost(ps_mc,     200).
ps_cost(ps_uart,   150).

% ── Explicit allow rules (normal mode) ──────────────────────────────────
% MC can access all internal components
allow(mc, C, normal) :- receiver(C), link(bus_mc, C).
% GS can reach radio_drv only (radio bridges to bus_mc)
allow(gs, radio_drv, normal).
% FC can access uart_drv
allow(fc, uart_drv, normal).

% ── Access needs (least-privilege ground truth) ─────────────────────────
% MC (mission computer): r+w to planner chain, read from sensors, no swu write
access_need(mc, fpln,        read).  access_need(mc, fpln,        write).
access_need(mc, fpln_filt,   read).  access_need(mc, fpln_filt,   write).
access_need(mc, geofence,    read).  access_need(mc, geofence,    write).
access_need(mc, wpm,         read).  access_need(mc, wpm,         write).
access_need(mc, cam_mgr,     read).  access_need(mc, cam_mgr,     write).
access_need(mc, uart_drv,    read).  access_need(mc, uart_drv,    write).
access_need(mc, nfzdb,       read).  % read-only: MC queries NFZ data
access_need(mc, attest_gate, read).  % read attestation results
access_need(mc, radio_drv,   read).  access_need(mc, radio_drv, write).

% GS (ground station): write commands to radio only
access_need(gs, radio_drv, write).
access_need(gs, radio_drv, read).    % receive telemetry

% FC (flight controller): r+w to uart_drv (serial commands/responses)
access_need(fc, uart_drv, read).  access_need(fc, uart_drv, write).

% ── Subject roles ───────────────────────────────────────────────────────
role(mc, mission_computer).
role(gs, ground_station).
role(fc, flight_controller).

role_need(mission_computer, C, read)  :- receiver(C), link(bus_mc, C).
role_need(mission_computer, C, write) :- receiver(C), link(bus_mc, C), not C = nfzdb.
role_need(ground_station, radio_drv, read).
role_need(ground_station, radio_drv, write).
role_need(flight_controller, uart_drv, read).
role_need(flight_controller, uart_drv, write).

% ── Mission context ─────────────────────────────────────────────────────
mission_phase(operational).
mission_phase(maintenance).
mission_phase(emergency).

% Operational: normal access per access_need
mission_access(M, C, Op, operational) :- access_need(M, C, Op).

% Maintenance: MC gets r+w to swu + wifi_drv (firmware update path)
mission_access(mc, swu,      read,  maintenance).
mission_access(mc, swu,      write, maintenance).
mission_access(mc, wifi_drv, read,  maintenance).
mission_access(mc, wifi_drv, write, maintenance).
mission_access(M, C, Op, maintenance) :- access_need(M, C, Op).

% Emergency: read-only for all masters (prevent state corruption)
mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).

% Policy exception: GS direct-to-MC bypass during emergency recovery
policy_exception(gs, fpln, write, emergency, reason(emergency_recovery)).

% ── Trust anchors ───────────────────────────────────────────────────────
hardware_rot(mc).          % seL4-verified mission computer
hardware_rot(fc).          % dedicated flight controller
hardware_rot(attest_gate). % CakeML-verified attestation

secure_boot(mc).
secure_boot(fc).
secure_boot(attest_gate).
secure_boot(geofence).
secure_boot(fpln_filt).

attested(mc).              % MC attests to GS via attestation gate
% gs is NOT attested (external entity, verified by attest_gate)
% fc is NOT attested (no TPM on simple RT controller)

signed_policy(ps_mc).      % MC policy server uses signed policies

key_storage(mc).
key_storage(attest_gate).
key_storage(nfzdb).        % NFZ database signed data

trusted_telemetry(mc).
trusted_telemetry(attest_gate).

% ── Services ────────────────────────────────────────────────────────────
service_component(flight_safety_svc, fpln).
service_component(flight_safety_svc, fpln_filt).
service_component(flight_safety_svc, geofence).
service_component(flight_safety_svc, wpm).
service_component(flight_safety_svc, uart_drv).
service_quorum(flight_safety_svc, 5).  % ALL required (single-string)

service_component(navigation_svc, nfzdb).
service_component(navigation_svc, geofence).
service_quorum(navigation_svc, 2).     % both required

service_component(surveillance_svc, cam_mgr).
service_quorum(surveillance_svc, 1).   % SPOF

service_component(comms_svc, radio_drv).
service_quorum(comms_svc, 1).          % SPOF

service_component(maintenance_svc, wifi_drv).
service_component(maintenance_svc, swu).
service_quorum(maintenance_svc, 2).    % both required for OTA update

% ── Control plane components ────────────────────────────────────────────
policy_server(ps_mc).
policy_server(ps_uart).
policy_enforcement_point(pep_mc).

pep_guards(pep_mc, C) :- receiver(C), link(bus_mc, C).

ps_governs_pep(ps_mc,   pep_mc).
ps_governs_pep(ps_uart,  pep_mc).

% ── Capabilities (mission-level functional assessment) ──────────────────
capability(flight_control).
capability_criticality(flight_control, essential).
capability_requires_service(flight_control, flight_safety_svc).
capability_requires_component(flight_control, fc).
capability_requires_component(flight_control, uart_drv).
capability_requires_access(flight_control, mc, wpm, write).
capability_requires_access(flight_control, mc, uart_drv, write).
capability_phase(flight_control, operational).
capability_phase(flight_control, emergency).

capability(navigation).
capability_criticality(navigation, essential).
capability_requires_service(navigation, navigation_svc).
capability_requires_component(navigation, geofence).
capability_requires_component(navigation, nfzdb).
capability_requires_access(navigation, mc, geofence, read).
capability_requires_access(navigation, mc, nfzdb, read).
capability_phase(navigation, operational).

capability(surveillance).
capability_criticality(surveillance, important).
capability_requires_service(surveillance, surveillance_svc).
capability_requires_component(surveillance, cam_mgr).
capability_requires_access(surveillance, mc, cam_mgr, read).
capability_phase(surveillance, operational).

capability(ground_comms).
capability_criticality(ground_comms, essential).
capability_requires_service(ground_comms, comms_svc).
capability_requires_component(ground_comms, radio_drv).
capability_requires_access(ground_comms, mc, radio_drv, read).
capability_requires_access(ground_comms, gs, radio_drv, write).
capability_phase(ground_comms, operational).
capability_phase(ground_comms, emergency).

capability(ota_update).
capability_criticality(ota_update, important).
capability_requires_service(ota_update, maintenance_svc).
capability_requires_component(ota_update, swu).
capability_requires_component(ota_update, wifi_drv).
capability_requires_access(ota_update, mc, swu, write).
capability_phase(ota_update, maintenance).

capability(policy_management).
capability_criticality(policy_management, essential).
capability_requires_component(policy_management, ps_mc).
capability_phase(policy_management, operational).
capability_phase(policy_management, emergency).

capability(attestation).
capability_criticality(attestation, essential).
capability_requires_component(attestation, attest_gate).
capability_requires_access(attestation, mc, attest_gate, read).
capability_phase(attestation, operational).
