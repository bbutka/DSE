%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% tgt_system_refsoc_inst.lp
%% Target: PYNQ-Z2 (Zynq-7000, xc7z020clg400-1)
%%
%% SecureSoC-16 Reference Architecture
%% ====================================
%% Generic reference SoC designed to exercise every DSE tool feature.
%% Matches the Python make_reference_soc() factory in asp_generator.py.
%%
%% Topology:
%%   3 masters  (arm_a53, arm_m4, dma0)
%%   3 buses    (axi_main, axi_sec, apb_periph)
%%  10 IP cores (crypto_eng, nvram, sensor_{a,b,c}, actuator, comm_eth,
%%               watchdog, gpio, debug_jtag)
%%   2 FWs      (fw_secure, fw_periph)
%%   2 PSs      (ps_main, ps_backup)
%%
%% Features exercised:
%%   - All 6 domain levels (untrusted .. root)
%%   - Full CIA triad (impact_avail on every component)
%%   - Exploitability range 1-5
%%   - Triple-redundant sensor group (g1)
%%   - Safety-critical components (crypto_eng, actuator, watchdog)
%%   - Untrusted network-facing component (comm_eth, exploit=5)
%%   - Debug port (debug_jtag, untrusted, exploit=5)
%%   - Dual-risk budget (Option A)
%%   - Policy exceptions across mission phases
%%   - All trust anchor types
%%
%% DUAL-RISK BUDGET
%% ================
%% max_security_risk = 4 — forces mac+ on high-impact non-redundant assets.
%%   Example: debug_jtag (untrusted, DB=0, EM=+2, imp=5):
%%     Risk = 5 + 0 + 2 - SP - LP  →  needs SP+LP >= 3  (mac+no_logging = 4+0 ✓)
%%   Example: comm_eth (untrusted, DB=0, EM=+2, imp_read=4):
%%     Risk = 4 + 0 + 2 - SP - LP  →  needs SP+LP >= 2  (mac+no_logging = 4+0 ✓)
%%   Example: nvram (privileged, DB=2, EM=-1, imp_write=5):
%%     Risk = 5 + 2 - 1 - SP - LP = 6 - SP - LP  →  needs SP+LP >= 2  (mac+no_logging ✓)
%%
%% max_avail_risk = 25 — permissive for sensor group.
%%   Sensor group (g1): size=3, floor = Mu*10 = 250
%%   For impact_avail=4: min risk = 4*250/100 = 10, well under 25.
%%   Allows all security choices, letting the minimiser drive selection.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% ── FPGA resource budget (PYNQ-Z2 xc7z020) ──────────────────────────────
system_capability(max_power,  15000).   % 15W
system_capability(max_luts,   53200).
system_capability(max_ffs,   106400).
system_capability(max_dsps,     220).
system_capability(max_lutram,  17400).
system_capability(max_bufgs,      32).
system_capability(max_bram,      140).
system_capability(max_bufg,       32).  % alias for opt_resource_enc.lp

% ── Dual-risk budget caps ────────────────────────────────────────────────
system_capability(max_security_risk, 4).   % additive cap: non-redundant
system_capability(max_avail_risk,   25).   % probabilistic cap: redundant group

% ── Masters ──────────────────────────────────────────────────────────────
master(arm_a53).
master(arm_m4).
master(dma0).

% ── Receiver components (risk model applies to these) ────────────────────
component(crypto_eng).
component(nvram).
component(sensor_a).
component(sensor_b).
component(sensor_c).
component(actuator).
component(comm_eth).
component(watchdog).
component(gpio).
component(debug_jtag).
component(ps_main).
component(ps_backup).

% ── Domains (all 6 levels exercised) ────────────────────────────────────
domain(arm_a53,    privileged).   % app processor
domain(arm_m4,     normal).       % RT processor
domain(dma0,       normal).       % DMA controller
domain(crypto_eng, root).         % crypto accelerator (highest trust)
domain(nvram,      privileged).   % secure storage
domain(sensor_a,   normal).       % temp sensor
domain(sensor_b,   normal).       % pressure sensor
domain(sensor_c,   normal).       % voltage monitor
domain(actuator,   privileged).   % motor/PWM (safety-critical)
domain(comm_eth,   untrusted).    % externally-facing Ethernet
domain(watchdog,   privileged).   % watchdog timer
domain(gpio,       low).          % low-trust peripheral
domain(debug_jtag, untrusted).    % debug port
domain(ps_main,    high).         % primary policy server
domain(ps_backup,  high).         % backup policy server

% ── Exploitability (CVSS-style, 1=hard, 3=neutral, 5=trivial) ──────────
exploitability(arm_a53,    2).
exploitability(arm_m4,     3).
exploitability(dma0,       4).    % DMA attack class
exploitability(crypto_eng, 1).    % hardened crypto IP
exploitability(nvram,      2).
exploitability(sensor_a,   3).
exploitability(sensor_b,   3).
exploitability(sensor_c,   3).
exploitability(actuator,   3).
exploitability(comm_eth,   5).    % network-facing, trivially exploitable
exploitability(watchdog,   2).
exploitability(gpio,       3).
exploitability(debug_jtag, 5).    % debug port, max exploitability

% ── Assets and impacts (CIA triad) ──────────────────────────────────────
% Format: asset(Component, AssetID, Action).
%         impact(AssetID, Action, ImpactValue).
%
% Masters have no receiver assets in this model (they initiate, not receive).
% Each IP core has read/write/avail assets based on its direction and impact.

% crypto_eng — root, safety-critical, bidirectional
asset(crypto_eng, crypto_engr1, read).
asset(crypto_eng, crypto_engr1, write).
asset(crypto_eng, crypto_engr1, avail).
impact(crypto_engr1, read,  4).
impact(crypto_engr1, write, 3).
impact(crypto_engr1, avail, 2).

% nvram — privileged, bidirectional
asset(nvram, nvramr1, read).
asset(nvram, nvramr1, write).
asset(nvram, nvramr1, avail).
impact(nvramr1, read,  5).
impact(nvramr1, write, 5).
impact(nvramr1, avail, 3).

% sensor_a — normal, input-only
asset(sensor_a, sensor_ar1, read).
asset(sensor_a, sensor_ar1, avail).
impact(sensor_ar1, read,  3).
impact(sensor_ar1, avail, 4).

% sensor_b — normal, input-only
asset(sensor_b, sensor_br1, read).
asset(sensor_b, sensor_br1, avail).
impact(sensor_br1, read,  3).
impact(sensor_br1, avail, 4).

% sensor_c — normal, input-only
asset(sensor_c, sensor_cr1, read).
asset(sensor_c, sensor_cr1, avail).
impact(sensor_cr1, read,  2).
impact(sensor_cr1, avail, 3).

% actuator — privileged, output-only, safety-critical
asset(actuator, actuatorr1, write).
asset(actuator, actuatorr1, avail).
impact(actuatorr1, write, 5).
impact(actuatorr1, avail, 5).

% comm_eth — untrusted, bidirectional
asset(comm_eth, comm_ethr1, read).
asset(comm_eth, comm_ethr1, write).
asset(comm_eth, comm_ethr1, avail).
impact(comm_ethr1, read,  4).
impact(comm_ethr1, write, 3).
impact(comm_ethr1, avail, 4).

% watchdog — privileged, low C/I but high A
asset(watchdog, watchdogr1, read).
asset(watchdog, watchdogr1, write).
asset(watchdog, watchdogr1, avail).
impact(watchdogr1, read,  1).
impact(watchdogr1, write, 2).
impact(watchdogr1, avail, 5).

% gpio — low domain, bidirectional
asset(gpio, gpior1, read).
asset(gpio, gpior1, write).
asset(gpio, gpior1, avail).
impact(gpior1, read,  1).
impact(gpior1, write, 2).
impact(gpior1, avail, 1).

% debug_jtag — untrusted, bidirectional (high C/I when exposed)
asset(debug_jtag, debug_jtagr1, read).
asset(debug_jtag, debug_jtagr1, write).
asset(debug_jtag, debug_jtagr1, avail).
impact(debug_jtagr1, read,  5).
impact(debug_jtagr1, write, 5).
impact(debug_jtagr1, avail, 2).

% ── Latency constraints ─────────────────────────────────────────────────
% Format: latency(Component, read|write, MaxCycles).
% 1000 = unconstrained.
latency(arm_a53,    read, 1000).
latency(arm_a53,    write, 1000).
latency(arm_m4,     read, 1000).
latency(arm_m4,     write, 1000).
latency(dma0,       read, 1000).
latency(dma0,       write, 1000).
latency(crypto_eng, read, 3).
latency(crypto_eng, write, 5).
latency(nvram,      read, 8).
latency(nvram,      write, 12).
latency(sensor_a,   read, 5).
latency(sensor_a,   write, 1000).
latency(sensor_b,   read, 5).
latency(sensor_b,   write, 1000).
latency(sensor_c,   read, 5).
latency(sensor_c,   write, 1000).
latency(actuator,   read, 1000).
latency(actuator,   write, 3).
latency(comm_eth,   read, 10).
latency(comm_eth,   write, 15).
latency(watchdog,   read, 2).
latency(watchdog,   write, 2).
latency(gpio,       read, 3).
latency(gpio,       write, 3).
latency(debug_jtag, read, 1000).
latency(debug_jtag, write, 1000).

% ── Redundancy group ────────────────────────────────────────────────────
redundant_group(g1, sensor_a).
redundant_group(g1, sensor_b).
redundant_group(g1, sensor_c).

% ── Trust anchors ────────────────────────────────────────────────────────
trust_anchor(arm_a53,    rot).
trust_anchor(arm_a53,    sboot).
trust_anchor(arm_a53,    attest).
trust_anchor(arm_a53,    key_storage).
trust_anchor(arm_m4,     sboot).
trust_anchor(crypto_eng, rot).
trust_anchor(crypto_eng, sboot).
trust_anchor(crypto_eng, key_storage).
trust_anchor(nvram,      rot).
trust_anchor(nvram,      key_storage).
trust_anchor(sensor_a,   sboot).
trust_anchor(sensor_b,   sboot).
trust_anchor(ps_main,    signed_policy).
trust_anchor(ps_main,    key_storage).

% ── Topology links (for standalone runs / Phase 2-3) ────────────────────
link(arm_a53, axi_main).
link(arm_m4,  axi_main).
link(dma0,    axi_main).
link(axi_main, axi_sec).
link(axi_sec,  crypto_eng).
link(axi_sec,  nvram).
link(axi_main,  apb_periph).
link(apb_periph, sensor_a).
link(apb_periph, sensor_b).
link(apb_periph, sensor_c).
link(apb_periph, actuator).
link(apb_periph, watchdog).
link(apb_periph, gpio).
link(apb_periph, debug_jtag).
link(axi_main, comm_eth).

% ── Security feature selection (choice domain for standalone solving) ────
% When running via the DSE tool, asp_generator.py emits these.
% For standalone Clingo runs: uncomment the choice rules below.
% 1 { selected_security(C, S) : security_feature(S) } 1 :- component(C).
% 1 { selected_logging(C, L)  : logging_feature(L)  } 1 :- component(C).
