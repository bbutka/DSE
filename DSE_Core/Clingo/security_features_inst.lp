% Minimal catalog for Phase 1 backend parity tests
security_feature(no_security).
realtime_feature(no_realtime).
power_cost(no_security, byAsset, 0).
power_cost(no_security, byComponent, 0).
power_cost(no_security, base, 0).
power_cost(no_realtime, base, 0).
exposure(no_security, 50).
realtime_detection(no_realtime, 20).
prob_lookup(no_security, no_realtime, 1000, 1000, 1225).
exploit_factor_map(1, 5).
exploit_factor_map(2, 7).
exploit_factor_map(3, 10).
exploit_factor_map(4, 14).
exploit_factor_map(5, 20).
luts(no_security, byAsset, 0).
luts(no_security, byComponent, 0).
luts(no_security, base, 0).
luts(no_realtime, base, 0).
ffs(no_security, byAsset, 0).
ffs(no_security, byComponent, 0).
ffs(no_security, base, 0).
ffs(no_realtime, base, 0).
dsps(no_security, byAsset, 0).
dsps(no_security, byComponent, 0).
dsps(no_security, base, 0).
dsps(no_realtime, base, 0).
lutram(no_security, byAsset, 0).
lutram(no_security, byComponent, 0).
lutram(no_security, base, 0).
lutram(no_realtime, base, 0).
bram(no_security, byAsset, 0).
bram(no_security, byComponent, 0).
bram(no_security, base, 0).
bram(no_realtime, base, 0).
bufg(no_security, byAsset, 0).
bufg(no_security, byComponent, 0).
bufg(no_security, base, 0).
bufg(no_realtime, base, 0).
latency_cost(no_security, 0).
latency_cost(no_realtime, 0).
