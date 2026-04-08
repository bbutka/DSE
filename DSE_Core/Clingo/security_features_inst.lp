% Auto-generated from ip_catalog/xilinx_ip_catalog.py
% Vivado catalog is the default source of truth for resource calculations.
% Do not edit manually unless you also update the catalog exporter.

% Security and realtime-detection feature declarations
security_feature(zero_trust).
security_feature(authenticated_encryption).
security_feature(dynamic_mac).
security_feature(mac).
security_feature(basic_access_control).
security_feature(no_security).
realtime_feature(runtime_attestation).
realtime_feature(bus_monitor).
realtime_feature(watchdog).
realtime_feature(no_realtime).

% Power costs (Vivado defaults)
power_cost(zero_trust, byAsset, 0).
power_cost(zero_trust, byComponent, 24).
power_cost(zero_trust, base, 0).
power_cost(authenticated_encryption, byAsset, 0).
power_cost(authenticated_encryption, byComponent, 20).
power_cost(authenticated_encryption, base, 0).
power_cost(dynamic_mac, byAsset, 0).
power_cost(dynamic_mac, byComponent, 18).
power_cost(dynamic_mac, base, 0).
power_cost(mac, byAsset, 0).
power_cost(mac, byComponent, 12).
power_cost(mac, base, 0).
power_cost(basic_access_control, byAsset, 0).
power_cost(basic_access_control, byComponent, 6).
power_cost(basic_access_control, base, 0).
power_cost(no_security, byAsset, 0).
power_cost(no_security, byComponent, 0).
power_cost(no_security, base, 0).
power_cost(runtime_attestation, base, 11).
power_cost(bus_monitor, base, 8).
power_cost(watchdog, base, 4).
power_cost(no_realtime, base, 0).

% Risk calculation values
exposure(zero_trust, 10).
exposure(authenticated_encryption, 15).
exposure(dynamic_mac, 20).
exposure(mac, 25).
exposure(basic_access_control, 35).
exposure(no_security, 50).
realtime_detection(runtime_attestation, 5).
realtime_detection(bus_monitor, 8).
realtime_detection(watchdog, 12).
realtime_detection(no_realtime, 20).
exploit_factor_map(1, 5).
exploit_factor_map(2, 7).
exploit_factor_map(3, 10).
exploit_factor_map(4, 14).
exploit_factor_map(5, 20).

% LUTS utilization (Vivado defaults)
luts(zero_trust, byAsset, 0).
luts(zero_trust, byComponent, 1200).
luts(zero_trust, base, 0).
luts(authenticated_encryption, byAsset, 0).
luts(authenticated_encryption, byComponent, 1050).
luts(authenticated_encryption, base, 0).
luts(dynamic_mac, byAsset, 0).
luts(dynamic_mac, byComponent, 950).
luts(dynamic_mac, base, 0).
luts(mac, byAsset, 0).
luts(mac, byComponent, 650).
luts(mac, base, 0).
luts(basic_access_control, byAsset, 0).
luts(basic_access_control, byComponent, 350).
luts(basic_access_control, base, 0).
luts(no_security, byAsset, 0).
luts(no_security, byComponent, 0).
luts(no_security, base, 0).
luts(runtime_attestation, base, 520).
luts(bus_monitor, base, 380).
luts(watchdog, base, 180).
luts(no_realtime, base, 0).

% FFS utilization (Vivado defaults)
ffs(zero_trust, byAsset, 0).
ffs(zero_trust, byComponent, 850).
ffs(zero_trust, base, 0).
ffs(authenticated_encryption, byAsset, 0).
ffs(authenticated_encryption, byComponent, 720).
ffs(authenticated_encryption, base, 0).
ffs(dynamic_mac, byAsset, 0).
ffs(dynamic_mac, byComponent, 680).
ffs(dynamic_mac, base, 0).
ffs(mac, byAsset, 0).
ffs(mac, byComponent, 420).
ffs(mac, base, 0).
ffs(basic_access_control, byAsset, 0).
ffs(basic_access_control, byComponent, 200).
ffs(basic_access_control, base, 0).
ffs(no_security, byAsset, 0).
ffs(no_security, byComponent, 0).
ffs(no_security, base, 0).
ffs(runtime_attestation, base, 480).
ffs(bus_monitor, base, 320).
ffs(watchdog, base, 220).
ffs(no_realtime, base, 0).

% DSPS utilization (Vivado defaults)
dsps(zero_trust, byAsset, 0).
dsps(zero_trust, byComponent, 0).
dsps(zero_trust, base, 0).
dsps(authenticated_encryption, byAsset, 0).
dsps(authenticated_encryption, byComponent, 0).
dsps(authenticated_encryption, base, 0).
dsps(dynamic_mac, byAsset, 0).
dsps(dynamic_mac, byComponent, 0).
dsps(dynamic_mac, base, 0).
dsps(mac, byAsset, 0).
dsps(mac, byComponent, 0).
dsps(mac, base, 0).
dsps(basic_access_control, byAsset, 0).
dsps(basic_access_control, byComponent, 0).
dsps(basic_access_control, base, 0).
dsps(no_security, byAsset, 0).
dsps(no_security, byComponent, 0).
dsps(no_security, base, 0).
dsps(runtime_attestation, base, 0).
dsps(bus_monitor, base, 0).
dsps(watchdog, base, 0).
dsps(no_realtime, base, 0).

% LUTRAM utilization (Vivado defaults)
lutram(zero_trust, byAsset, 0).
lutram(zero_trust, byComponent, 64).
lutram(zero_trust, base, 0).
lutram(authenticated_encryption, byAsset, 0).
lutram(authenticated_encryption, byComponent, 0).
lutram(authenticated_encryption, base, 0).
lutram(dynamic_mac, byAsset, 0).
lutram(dynamic_mac, byComponent, 0).
lutram(dynamic_mac, base, 0).
lutram(mac, byAsset, 0).
lutram(mac, byComponent, 0).
lutram(mac, base, 0).
lutram(basic_access_control, byAsset, 0).
lutram(basic_access_control, byComponent, 0).
lutram(basic_access_control, base, 0).
lutram(no_security, byAsset, 0).
lutram(no_security, byComponent, 0).
lutram(no_security, base, 0).
lutram(runtime_attestation, base, 0).
lutram(bus_monitor, base, 0).
lutram(watchdog, base, 0).
lutram(no_realtime, base, 0).

% BRAM utilization (Vivado defaults)
bram(zero_trust, byAsset, 0).
bram(zero_trust, byComponent, 0).
bram(zero_trust, base, 0).
bram(authenticated_encryption, byAsset, 0).
bram(authenticated_encryption, byComponent, 0).
bram(authenticated_encryption, base, 0).
bram(dynamic_mac, byAsset, 0).
bram(dynamic_mac, byComponent, 0).
bram(dynamic_mac, base, 0).
bram(mac, byAsset, 0).
bram(mac, byComponent, 0).
bram(mac, base, 0).
bram(basic_access_control, byAsset, 0).
bram(basic_access_control, byComponent, 0).
bram(basic_access_control, base, 0).
bram(no_security, byAsset, 0).
bram(no_security, byComponent, 0).
bram(no_security, base, 0).
bram(runtime_attestation, base, 2).
bram(bus_monitor, base, 0).
bram(watchdog, base, 1).
bram(no_realtime, base, 0).

% BUFG utilization (Vivado defaults)
bufg(zero_trust, byAsset, 0).
bufg(zero_trust, byComponent, 0).
bufg(zero_trust, base, 0).
bufg(authenticated_encryption, byAsset, 0).
bufg(authenticated_encryption, byComponent, 0).
bufg(authenticated_encryption, base, 0).
bufg(dynamic_mac, byAsset, 0).
bufg(dynamic_mac, byComponent, 0).
bufg(dynamic_mac, base, 0).
bufg(mac, byAsset, 0).
bufg(mac, byComponent, 0).
bufg(mac, base, 0).
bufg(basic_access_control, byAsset, 0).
bufg(basic_access_control, byComponent, 0).
bufg(basic_access_control, base, 0).
bufg(no_security, byAsset, 0).
bufg(no_security, byComponent, 0).
bufg(no_security, base, 0).
bufg(runtime_attestation, base, 0).
bufg(bus_monitor, base, 0).
bufg(watchdog, base, 0).
bufg(no_realtime, base, 0).

% Latency costs (Vivado defaults)
latency_cost(zero_trust, 3).
latency_cost(authenticated_encryption, 4).
latency_cost(dynamic_mac, 6).
latency_cost(mac, 4).
latency_cost(basic_access_control, 2).
latency_cost(no_security, 0).
latency_cost(runtime_attestation, 2).
latency_cost(bus_monitor, 1).
latency_cost(watchdog, 1).
latency_cost(no_realtime, 0).
