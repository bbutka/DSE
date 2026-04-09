% Pixhawk 6X platform generated instance facts
%
% Generated from the Python NetworkModel factory for reproducibility and
% direct Clingo inspection. The integrated DSE_Core pipeline continues to
% generate instance facts dynamically at runtime.
% Auto-generated ASP facts for network: Pixhawk 6X Platform

% Components
component(io_mcu).
component(imu_1).
component(imu_2).
component(imu_3).
component(baro_1).
component(baro_2).
component(mag).
component(se050).

% Assets
asset(imu_1, imu1_data, read).
asset(imu_1, imu1_data, avail).
asset(imu_2, imu2_data, read).
asset(imu_2, imu2_data, avail).
asset(imu_3, imu3_data, read).
asset(imu_3, imu3_data, avail).
asset(baro_1, baro1_data, read).
asset(baro_1, baro1_data, avail).
asset(baro_2, baro2_data, read).
asset(baro_2, baro2_data, avail).
asset(mag, mag_data, read).
asset(mag, mag_data, avail).
asset(se050, se050_ctrl, read).
asset(se050, se050_ctrl, write).
asset(se050, se050_ctrl, avail).
asset(io_mcu, px4io_status, read).
asset(io_mcu, px4io_status, write).
asset(io_mcu, px4io_status, avail).

% Asset impact values (C = read, I = write, A = avail)
impact(imu1_data, read,  4).
impact(imu1_data, avail, 4).
impact(imu2_data, read,  4).
impact(imu2_data, avail, 4).
impact(imu3_data, read,  4).
impact(imu3_data, avail, 4).
impact(baro1_data, read,  3).
impact(baro1_data, avail, 3).
impact(baro2_data, read,  3).
impact(baro2_data, avail, 3).
impact(mag_data, read,  2).
impact(mag_data, avail, 2).
impact(se050_ctrl, read,  5).
impact(se050_ctrl, write, 5).
impact(se050_ctrl, avail, 2).
impact(px4io_status, read,  2).
impact(px4io_status, write, 4).
impact(px4io_status, avail, 5).

% Allowable latency per asset
allowable_latency(imu1_data, read,  4).
allowable_latency(imu2_data, read,  4).
allowable_latency(imu3_data, read,  4).
allowable_latency(baro1_data, read,  8).
allowable_latency(baro2_data, read,  8).
allowable_latency(mag_data, read,  8).
allowable_latency(se050_ctrl, read,  10).
allowable_latency(se050_ctrl, write, 10).
allowable_latency(px4io_status, read,  8).
allowable_latency(px4io_status, write, 8).

% Redundancy groups
redundant_group(imu_group, imu_1).
redundant_group(imu_group, imu_2).
redundant_group(imu_group, imu_3).
redundant_group(baro_group, baro_1).
redundant_group(baro_group, baro_2).

% ZTA topology â€” masters, receivers, buses, links
master(fmu_h753).
receiver(io_mcu).
receiver(imu_1).
receiver(imu_2).
receiver(imu_3).
receiver(baro_1).
receiver(baro_2).
receiver(mag).
receiver(se050).
bus(imu_bus_1).
bus(imu_bus_2).
bus(imu_bus_3).
bus(baro_bus_1).
bus(baro_bus_2).
bus(mag_bus).
bus(gps1_port).
bus(gps2_port).
bus(telem1_port).
bus(telem2_port).
bus(telem3_port).
bus(uart4_i2c_port).
bus(eth_port).
bus(spi5_ext).
bus(can1).
bus(can2).
bus(px4io_link).

link(fmu_h753, imu_bus_1).
link(imu_bus_1, imu_1).
link(fmu_h753, imu_bus_2).
link(imu_bus_2, imu_2).
link(fmu_h753, imu_bus_3).
link(imu_bus_3, imu_3).
link(fmu_h753, baro_bus_1).
link(baro_bus_1, baro_1).
link(fmu_h753, baro_bus_2).
link(baro_bus_2, baro_2).
link(fmu_h753, mag_bus).
link(mag_bus, mag).
link(fmu_h753, gps1_port).
link(fmu_h753, gps2_port).
link(fmu_h753, telem1_port).
link(fmu_h753, telem2_port).
link(fmu_h753, telem3_port).
link(fmu_h753, uart4_i2c_port).
link(fmu_h753, eth_port).
link(fmu_h753, spi5_ext).
link(fmu_h753, can1).
link(fmu_h753, can2).
link(fmu_h753, px4io_link).
link(px4io_link, io_mcu).
link(fmu_h753, se050).

% Trust domains (untrusted=0 | low=0 | normal=1 | privileged=2 | high=3 | root=3)
domain(fmu_h753, privileged).
domain(io_mcu, normal).
domain(ps_fmu, root).
domain(imu_1, high).
domain(imu_2, high).
domain(imu_3, high).
domain(baro_1, normal).
domain(baro_2, normal).
domain(mag, normal).
domain(se050, root).

% Exploitability: 1=hard, 3=neutral, 5=trivial (default 3 when omitted)
exploitability(fmu_h753, 3).  % explicit: USB/serial/MAVLink parsing attack surface
exploitability(io_mcu, 2).
exploitability(imu_1, 2).
exploitability(imu_2, 2).
exploitability(imu_3, 2).
exploitability(baro_1, 2).
exploitability(baro_2, 2).
exploitability(mag, 2).
exploitability(se050, 1).

% Critical and safety-critical IPs
critical(io_mcu).
critical(imu_1).
critical(imu_2).
critical(imu_3).
critical(baro_1).
critical(baro_2).
critical(mag).
critical(se050).
safety_critical(io_mcu).
safety_critical(imu_1).
safety_critical(imu_2).
safety_critical(imu_3).

% Candidate firewalls and policy servers
cand_fw(pep_px4io).
cand_fw(pep_se050).
cand_ps(ps_fmu).

% On-path and ip_loc facts
on_path(pep_px4io, fmu_h753, io_mcu).
on_path(pep_se050, fmu_h753, se050).
ip_loc(io_mcu, pep_px4io).
ip_loc(se050, pep_se050).

% Firewall governance by policy server
governs(ps_fmu, pep_px4io).
governs(ps_fmu, pep_se050).

% Hardware costs
fw_cost(pep_px4io, 120).
fw_cost(pep_se050, 100).
ps_cost(ps_fmu, 180).

% System capabilities (resource budgets)
system_capability(max_power, 15000).
system_capability(max_luts, 53200).
system_capability(max_ffs, 106400).
system_capability(max_dsps, 220).
system_capability(max_lutram, 17400).
system_capability(max_bufgs, 32).
system_capability(max_bram, 140).
system_capability(max_security_risk, 60).
system_capability(max_avail_risk, 25).
system_capability(max_attack_depth, 8).

% Explicit allow rules (normal mode)
allow(fmu_h753, imu_1, normal).
allow(fmu_h753, imu_2, normal).
allow(fmu_h753, imu_3, normal).
allow(fmu_h753, baro_1, normal).
allow(fmu_h753, baro_2, normal).
allow(fmu_h753, mag, normal).
allow(fmu_h753, se050, normal).
allow(fmu_h753, se050, normal).
allow(fmu_h753, io_mcu, normal).
allow(fmu_h753, io_mcu, normal).

% Least-privilege access needs
access_need(fmu_h753, imu_1, read).
access_need(fmu_h753, imu_2, read).
access_need(fmu_h753, imu_3, read).
access_need(fmu_h753, baro_1, read).
access_need(fmu_h753, baro_2, read).
access_need(fmu_h753, mag, read).
access_need(fmu_h753, se050, read).
access_need(fmu_h753, se050, write).
access_need(fmu_h753, io_mcu, read).
access_need(fmu_h753, io_mcu, write).

% Subject roles
role(fmu_h753, flight_controller).

% Trust anchors and attestation
hardware_rot(fmu_h753).
secure_boot(fmu_h753).
attested(fmu_h753).
hardware_rot(se050).
key_storage(se050).
signed_policy(ps_fmu).

% Services
service_component(attitude_sensor_svc, imu_1).
service_component(attitude_sensor_svc, imu_2).
service_component(attitude_sensor_svc, imu_3).
service_quorum(attitude_sensor_svc, 2).
service_component(altitude_sensor_svc, baro_1).
service_component(altitude_sensor_svc, baro_2).
service_quorum(altitude_sensor_svc, 1).
service_component(mag_sensor_svc, mag).
service_quorum(mag_sensor_svc, 1).
service_component(crypto_svc, se050).
service_quorum(crypto_svc, 1).
service_component(io_failsafe_svc, io_mcu).
service_quorum(io_failsafe_svc, 1).

% Control plane
policy_server(ps_fmu).
policy_enforcement_point(pep_px4io).
policy_enforcement_point(pep_se050).
pep_guards(pep_px4io, io_mcu).
pep_guards(pep_se050, se050).
ps_governs_pep(ps_fmu, pep_px4io).
ps_governs_pep(ps_fmu, pep_se050).

% Mission phases
mission_phase(operational).
mission_phase(maintenance).
mission_phase(emergency).

% Mission access rules
mission_access(M, C, Op, operational) :- access_need(M, C, Op).
mission_access(fmu_h753, C, read,  maintenance) :- receiver(C).
mission_access(fmu_h753, C, write, maintenance) :- receiver(C).
mission_access(M, C, read, emergency) :- master(M), receiver(C), access_need(M, C, read).

% Role-level access needs
role_need(flight_controller, C, read)  :- receiver(C), domain(C, high).
role_need(flight_controller, C, read)  :- receiver(C), domain(C, root).

% Static risk weights for amplification-aware Phase 1 objective
% risk_weight(Asset, W): W in [10,50]; higher = amplified more in Phase 3
% Note: fmu_h753 is a master with no asset facts in Phase 1.
% Its risk is captured via Phase 3 scenario compromise, not Phase 1 risk weights.
% risk_weight(fmu_h753r1, 50) removed — the asset fmu_h753r1 does not exist.
risk_weight(px4io_status, 35).
risk_weight(imu1_data, 45).
risk_weight(imu2_data, 45).
risk_weight(imu3_data, 45).
risk_weight(baro1_data, 15).
risk_weight(baro2_data, 15).
risk_weight(mag_data, 15).
risk_weight(se050_ctrl, 25).

% Mission capabilities
capability(flight_stabilization_base).
capability_criticality(flight_stabilization_base, essential).
% flight_stabilization_base: On-board inertial and barometric sensing for flight stabilization
% Capability depends on SERVICES (with quorum), not specific sensor instances.
% attitude_sensor_svc requires 2-of-3 IMUs; altitude_sensor_svc requires 1-of-2 baros.
% Previous version pinned to imu_1/baro_1 specifically, inflating capability loss count.
capability_requires_service(flight_stabilization_base, attitude_sensor_svc).
capability_requires_service(flight_stabilization_base, altitude_sensor_svc).
capability_requires_component(flight_stabilization_base, fmu_h753).
capability_phase(flight_stabilization_base, operational).
capability_phase(flight_stabilization_base, emergency).
capability(failsafe_io).
capability_criticality(failsafe_io, essential).
% failsafe_io: Independent IO processing path for RC and failsafe functions
capability_requires_service(failsafe_io, io_failsafe_svc).
capability_requires_component(failsafe_io, io_mcu).
capability_requires_access(failsafe_io, fmu_h753, io_mcu, write).
capability_phase(failsafe_io, operational).
capability_phase(failsafe_io, emergency).
capability(crypto_anchor).
capability_criticality(crypto_anchor, important).
% crypto_anchor: Board-integrated hardware root of trust and key handling
capability_requires_service(crypto_anchor, crypto_svc).
capability_requires_component(crypto_anchor, se050).
capability_requires_access(crypto_anchor, fmu_h753, se050, read).
capability_requires_access(crypto_anchor, fmu_h753, se050, write).
capability_phase(crypto_anchor, operational).
capability_phase(crypto_anchor, maintenance).
capability_phase(crypto_anchor, emergency).
