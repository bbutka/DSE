% Pixhawk 6X UAV generated instance facts
%
% Generated from the Python NetworkModel factory for reproducibility and
% direct Clingo inspection. The integrated DSE_Core pipeline continues to
% generate instance facts dynamically at runtime.
% Auto-generated ASP facts for network: Pixhawk 6X UAV

% Components
component(io_mcu).
component(imu_1).
component(imu_2).
component(imu_3).
component(baro_1).
component(baro_2).
component(mag).
component(se050).
component(gps_1).
component(gps_2).
component(telem_radio).
component(rc_receiver).
component(esc_bus_1).
component(esc_bus_2).
component(companion).
component(camera).
component(flash_fram).

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
asset(gps_1, gps1_nav, read).
asset(gps_1, gps1_nav, avail).
asset(gps_2, gps2_nav, read).
asset(gps_2, gps2_nav, avail).
asset(telem_radio, telem_link, read).
asset(telem_radio, telem_link, write).
asset(telem_radio, telem_link, avail).
asset(rc_receiver, rc_input, read).
asset(rc_receiver, rc_input, avail).
asset(esc_bus_1, motor_cmd_1, write).
asset(esc_bus_1, motor_cmd_1, avail).
asset(esc_bus_2, motor_cmd_2, write).
asset(esc_bus_2, motor_cmd_2, avail).
asset(companion, companion_eth, read).
asset(companion, companion_eth, write).
asset(companion, companion_eth, avail).
asset(camera, camera_stream, read).
asset(camera, camera_stream, avail).
asset(flash_fram, log_store, read).
asset(flash_fram, log_store, write).
asset(flash_fram, log_store, avail).

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
impact(gps1_nav, read,  4).
impact(gps1_nav, avail, 4).
impact(gps2_nav, read,  4).
impact(gps2_nav, avail, 4).
impact(telem_link, read,  4).
impact(telem_link, write, 4).
impact(telem_link, avail, 4).
impact(rc_input, read,  2).
impact(rc_input, avail, 5).
impact(motor_cmd_1, write, 5).
impact(motor_cmd_1, avail, 5).
impact(motor_cmd_2, write, 5).
impact(motor_cmd_2, avail, 5).
impact(companion_eth, read,  3).
impact(companion_eth, write, 3).
impact(companion_eth, avail, 3).
impact(camera_stream, read,  3).
impact(camera_stream, avail, 2).
impact(log_store, read,  3).
impact(log_store, write, 4).
impact(log_store, avail, 3).

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
allowable_latency(gps1_nav, read,  12).
allowable_latency(gps2_nav, read,  12).
allowable_latency(telem_link, read,  15).
allowable_latency(telem_link, write, 15).
allowable_latency(rc_input, read,  20).
allowable_latency(motor_cmd_1, write, 5).
allowable_latency(motor_cmd_2, write, 5).
allowable_latency(companion_eth, read,  20).
allowable_latency(companion_eth, write, 20).
allowable_latency(camera_stream, read,  20).
allowable_latency(log_store, read,  12).
allowable_latency(log_store, write, 12).

% Redundancy groups
redundant_group(imu_group, imu_1).
redundant_group(imu_group, imu_2).
redundant_group(imu_group, imu_3).
redundant_group(baro_group, baro_1).
redundant_group(baro_group, baro_2).
redundant_group(gps_group, gps_1).
redundant_group(gps_group, gps_2).
redundant_group(motor_bus_group, esc_bus_1).
redundant_group(motor_bus_group, esc_bus_2).

% ZTA topology â€” masters, receivers, buses, links
master(fmu_h753).
master(ground_station).
receiver(io_mcu).
receiver(imu_1).
receiver(imu_2).
receiver(imu_3).
receiver(baro_1).
receiver(baro_2).
receiver(mag).
receiver(se050).
receiver(gps_1).
receiver(gps_2).
receiver(telem_radio).
receiver(rc_receiver).
receiver(esc_bus_1).
receiver(esc_bus_2).
receiver(companion).
receiver(camera).
receiver(flash_fram).
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
link(ground_station, telem_radio).
link(fmu_h753, gps1_port).
link(gps1_port, gps_1).
link(fmu_h753, gps2_port).
link(gps2_port, gps_2).
link(fmu_h753, telem1_port).
link(telem1_port, telem_radio).
link(fmu_h753, px4io_link).
link(px4io_link, rc_receiver).
link(fmu_h753, can1).
link(can1, esc_bus_1).
link(fmu_h753, can2).
link(can2, esc_bus_2).
link(fmu_h753, eth_port).
link(eth_port, companion).
link(companion, camera).
link(fmu_h753, spi5_ext).
link(spi5_ext, flash_fram).

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
domain(ground_station, untrusted).
domain(gps_1, low).
domain(gps_2, low).
domain(telem_radio, untrusted).
domain(rc_receiver, low).
domain(esc_bus_1, privileged).
domain(esc_bus_2, privileged).
domain(companion, normal).
domain(camera, normal).
domain(flash_fram, privileged).

% Exploitability: 1=hard, 3=neutral, 5=trivial (default 3 when omitted)
exploitability(io_mcu, 2).
exploitability(imu_1, 2).
exploitability(imu_2, 2).
exploitability(imu_3, 2).
exploitability(baro_1, 2).
exploitability(baro_2, 2).
exploitability(mag, 2).
exploitability(se050, 1).
exploitability(gps_1, 4).
exploitability(gps_2, 4).
exploitability(telem_radio, 5).
exploitability(rc_receiver, 4).
exploitability(esc_bus_1, 2).
exploitability(esc_bus_2, 2).
exploitability(companion, 4).
exploitability(flash_fram, 2).

% Critical and safety-critical IPs
critical(io_mcu).
critical(imu_1).
critical(imu_2).
critical(imu_3).
critical(baro_1).
critical(baro_2).
critical(mag).
critical(se050).
critical(gps_1).
critical(gps_2).
critical(telem_radio).
critical(rc_receiver).
critical(esc_bus_1).
critical(esc_bus_2).
critical(companion).
critical(flash_fram).
safety_critical(io_mcu).
safety_critical(imu_1).
safety_critical(imu_2).
safety_critical(imu_3).
safety_critical(rc_receiver).
safety_critical(esc_bus_1).
safety_critical(esc_bus_2).

% Candidate firewalls and policy servers
cand_fw(pep_px4io).
cand_fw(pep_se050).
cand_fw(pep_telem1).
cand_fw(pep_eth).
cand_fw(pep_can1).
cand_fw(pep_can2).
cand_fw(pep_gps2).
cand_ps(ps_fmu).

% On-path and ip_loc facts
on_path(pep_px4io, fmu_h753, io_mcu).
on_path(pep_se050, fmu_h753, se050).
on_path(pep_telem1, fmu_h753, telem_radio).
on_path(pep_telem1, ground_station, telem_radio).
on_path(pep_eth, fmu_h753, companion).
on_path(pep_can1, fmu_h753, esc_bus_1).
on_path(pep_can2, fmu_h753, esc_bus_2).
on_path(pep_gps2, fmu_h753, gps_2).
ip_loc(io_mcu, pep_px4io).
ip_loc(se050, pep_se050).
ip_loc(telem_radio, pep_telem1).
ip_loc(companion, pep_eth).
ip_loc(esc_bus_1, pep_can1).
ip_loc(esc_bus_2, pep_can2).
ip_loc(gps_2, pep_gps2).

% Firewall governance by policy server
governs(ps_fmu, pep_px4io).
governs(ps_fmu, pep_se050).
governs(ps_fmu, pep_telem1).
governs(ps_fmu, pep_eth).
governs(ps_fmu, pep_can1).
governs(ps_fmu, pep_can2).
governs(ps_fmu, pep_gps2).

% Hardware costs
fw_cost(pep_px4io, 120).
fw_cost(pep_se050, 100).
fw_cost(pep_telem1, 160).
fw_cost(pep_eth, 180).
fw_cost(pep_can1, 140).
fw_cost(pep_can2, 140).
fw_cost(pep_gps2, 110).
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
allow(ground_station, telem_radio, normal).
allow(ground_station, telem_radio, normal).
allow(fmu_h753, gps_1, normal).
allow(fmu_h753, gps_2, normal).
allow(fmu_h753, telem_radio, normal).
allow(fmu_h753, telem_radio, normal).
allow(fmu_h753, rc_receiver, normal).
allow(fmu_h753, esc_bus_1, normal).
allow(fmu_h753, esc_bus_2, normal).
allow(fmu_h753, companion, normal).
allow(fmu_h753, companion, normal).
allow(fmu_h753, camera, normal).
allow(fmu_h753, flash_fram, normal).
allow(fmu_h753, flash_fram, normal).

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
access_need(ground_station, telem_radio, read).
access_need(ground_station, telem_radio, write).
access_need(fmu_h753, gps_1, read).
access_need(fmu_h753, gps_2, read).
access_need(fmu_h753, telem_radio, read).
access_need(fmu_h753, telem_radio, write).
access_need(fmu_h753, rc_receiver, read).
access_need(fmu_h753, esc_bus_1, write).
access_need(fmu_h753, esc_bus_2, write).
access_need(fmu_h753, companion, read).
access_need(fmu_h753, companion, write).
access_need(fmu_h753, camera, read).
access_need(fmu_h753, flash_fram, read).
access_need(fmu_h753, flash_fram, write).

% Subject roles
role(fmu_h753, flight_controller).
role(ground_station, external_operator).

% Policy exceptions
policy_exception(fmu_h753, telem_radio, write, emergency, reason(status_broadcast)).
policy_exception(fmu_h753, flash_fram, write, maintenance, reason(log_export)).

% Trust anchors and attestation
hardware_rot(fmu_h753).
secure_boot(fmu_h753).
attested(fmu_h753).
hardware_rot(se050).
key_storage(se050).
signed_policy(ps_fmu).

% Services
service_component(attitude_svc, imu_1).
service_component(attitude_svc, imu_2).
service_component(attitude_svc, imu_3).
service_quorum(attitude_svc, 2).
service_component(altitude_svc, baro_1).
service_component(altitude_svc, baro_2).
service_quorum(altitude_svc, 1).
service_component(navigation_svc, gps_1).
service_component(navigation_svc, gps_2).
service_quorum(navigation_svc, 1).
service_component(motor_svc, esc_bus_1).
service_component(motor_svc, esc_bus_2).
service_quorum(motor_svc, 1).
service_component(comms_svc, telem_radio).
service_quorum(comms_svc, 1).
service_component(failsafe_svc, io_mcu).
service_component(failsafe_svc, rc_receiver).
service_quorum(failsafe_svc, 2).
service_component(crypto_svc, se050).
service_quorum(crypto_svc, 1).
service_component(payload_svc, companion).
service_component(payload_svc, camera).
service_quorum(payload_svc, 2).
service_component(logging_svc, flash_fram).
service_quorum(logging_svc, 1).

% Control plane
policy_server(ps_fmu).
policy_enforcement_point(pep_px4io).
policy_enforcement_point(pep_se050).
policy_enforcement_point(pep_telem1).
policy_enforcement_point(pep_eth).
policy_enforcement_point(pep_can1).
policy_enforcement_point(pep_can2).
policy_enforcement_point(pep_gps2).
pep_guards(pep_px4io, io_mcu).
pep_guards(pep_se050, se050).
pep_guards(pep_telem1, telem_radio).
pep_guards(pep_eth, companion).
pep_guards(pep_can1, esc_bus_1).
pep_guards(pep_can2, esc_bus_2).
pep_guards(pep_gps2, gps_2).
ps_governs_pep(ps_fmu, pep_px4io).
ps_governs_pep(ps_fmu, pep_se050).
ps_governs_pep(ps_fmu, pep_telem1).
ps_governs_pep(ps_fmu, pep_eth).
ps_governs_pep(ps_fmu, pep_can1).
ps_governs_pep(ps_fmu, pep_can2).
ps_governs_pep(ps_fmu, pep_gps2).

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
role_need(external_operator, C, read)  :- receiver(C), domain(C, high).
role_need(external_operator, C, read)  :- receiver(C), domain(C, root).

% Static risk weights for amplification-aware Phase 1 objective
% risk_weight(Asset, W): W in [10,50]; higher = amplified more in Phase 3
risk_weight(fmu_h753r1, 50).
risk_weight(px4io_status, 35).
risk_weight(imu1_data, 45).
risk_weight(imu2_data, 45).
risk_weight(imu3_data, 45).
risk_weight(baro1_data, 15).
risk_weight(baro2_data, 15).
risk_weight(mag_data, 15).
risk_weight(se050_ctrl, 25).
risk_weight(ground_stationr1, 30).
risk_weight(gps1_nav, 15).
risk_weight(gps2_nav, 15).
risk_weight(telem_link, 15).
risk_weight(rc_input, 35).
risk_weight(motor_cmd_1, 45).
risk_weight(motor_cmd_2, 45).
risk_weight(companion_eth, 15).
risk_weight(camera_stream, 15).
risk_weight(log_store, 25).

% Mission capabilities
capability(flight_control).
capability_criticality(flight_control, essential).
% flight_control: Stabilized flight using inertial sensing and actuator command paths
capability_requires_service(flight_control, attitude_svc).
capability_requires_service(flight_control, motor_svc).
capability_requires_component(flight_control, fmu_h753).
% Removed: capability_requires_access pinning to imu_1/esc_bus_1.
% The service quorum (attitude_svc 2/3, motor_svc 1/2) correctly models
% redundancy; pinning to specific instances inflated capability loss count.
capability_phase(flight_control, operational).
capability_phase(flight_control, emergency).
capability(navigation).
capability_criticality(navigation, essential).
% navigation: Position and altitude estimation using dual GPS and barometric sensing
capability_requires_service(navigation, navigation_svc).
capability_requires_service(navigation, altitude_svc).
% Removed: capability_requires_access pinning to gps_1/baro_1.
% Services (navigation_svc 1/2, altitude_svc 1/2) handle redundancy.
capability_phase(navigation, operational).
capability(ground_comms).
capability_criticality(ground_comms, essential).
% ground_comms: Bidirectional telemetry exchange with the ground station
capability_requires_service(ground_comms, comms_svc).
capability_requires_component(ground_comms, telem_radio).
capability_requires_access(ground_comms, fmu_h753, telem_radio, read).
capability_requires_access(ground_comms, fmu_h753, telem_radio, write).
capability_phase(ground_comms, operational).
capability_phase(ground_comms, emergency).
capability(rc_override).
capability_criticality(rc_override, essential).
% rc_override: Independent RC-based override and failsafe path
capability_requires_service(rc_override, failsafe_svc).
capability_requires_component(rc_override, io_mcu).
capability_requires_component(rc_override, rc_receiver).
capability_requires_access(rc_override, fmu_h753, rc_receiver, read).
capability_phase(rc_override, operational).
capability_phase(rc_override, emergency).
capability(surveillance).
capability_criticality(surveillance, important).
% surveillance: Payload observation path via companion compute and camera
capability_requires_service(surveillance, payload_svc).
capability_requires_component(surveillance, companion).
capability_requires_component(surveillance, camera).
capability_requires_access(surveillance, fmu_h753, companion, read).
capability_phase(surveillance, operational).
capability(crypto_ops).
capability_criticality(crypto_ops, important).
% crypto_ops: Hardware-rooted cryptographic operations and key handling
capability_requires_service(crypto_ops, crypto_svc).
capability_requires_component(crypto_ops, se050).
capability_requires_access(crypto_ops, fmu_h753, se050, read).
capability_requires_access(crypto_ops, fmu_h753, se050, write).
capability_phase(crypto_ops, operational).
capability_phase(crypto_ops, maintenance).
capability(logging).
capability_criticality(logging, important).
% logging: Persistent flight logging to SPI-attached storage
capability_requires_service(logging, logging_svc).
capability_requires_component(logging, flash_fram).
capability_requires_access(logging, fmu_h753, flash_fram, read).
capability_requires_access(logging, fmu_h753, flash_fram, write).
capability_phase(logging, operational).
capability_phase(logging, maintenance).
