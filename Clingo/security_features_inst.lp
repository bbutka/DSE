% Auto-generated from ip_catalog/xilinx_ip_catalog.py
% Vivado catalog is the default source of truth for resource calculations.
% Do not edit manually unless you also update the catalog exporter.

% Security and logging feature declarations
security_feature(zero_trust).
security_feature(mac).
security_feature(dynamic_mac).
logging_feature(zero_trust_logger).
logging_feature(some_logging).
logging_feature(no_logging).

% Power costs (Vivado defaults)
power_cost(zero_trust, byAsset, 0).
power_cost(zero_trust, byComponent, 24).
power_cost(zero_trust, base, 0).
power_cost(mac, byAsset, 0).
power_cost(mac, byComponent, 12).
power_cost(mac, base, 0).
power_cost(dynamic_mac, byAsset, 0).
power_cost(dynamic_mac, byComponent, 18).
power_cost(dynamic_mac, base, 0).
power_cost(zero_trust_logger, base, 11).
power_cost(some_logging, base, 4).
power_cost(no_logging, base, 0).

% Risk calculation values
vulnerability(zero_trust, 10).
vulnerability(mac, 30).
vulnerability(dynamic_mac, 20).
logging(zero_trust_logger, 5).
logging(some_logging, 10).
logging(no_logging, 20).

% LUTS utilization (Vivado defaults)
luts(zero_trust, byAsset, 0).
luts(zero_trust, byComponent, 1200).
luts(zero_trust, base, 0).
luts(mac, byAsset, 0).
luts(mac, byComponent, 650).
luts(mac, base, 0).
luts(dynamic_mac, byAsset, 0).
luts(dynamic_mac, byComponent, 950).
luts(dynamic_mac, base, 0).
luts(zero_trust_logger, base, 520).
luts(some_logging, base, 180).
luts(no_logging, base, 0).

% FFS utilization (Vivado defaults)
ffs(zero_trust, byAsset, 0).
ffs(zero_trust, byComponent, 850).
ffs(zero_trust, base, 0).
ffs(mac, byAsset, 0).
ffs(mac, byComponent, 420).
ffs(mac, base, 0).
ffs(dynamic_mac, byAsset, 0).
ffs(dynamic_mac, byComponent, 680).
ffs(dynamic_mac, base, 0).
ffs(zero_trust_logger, base, 480).
ffs(some_logging, base, 220).
ffs(no_logging, base, 0).

% DSPS utilization (Vivado defaults)
dsps(zero_trust, byAsset, 0).
dsps(zero_trust, byComponent, 0).
dsps(zero_trust, base, 0).
dsps(mac, byAsset, 0).
dsps(mac, byComponent, 0).
dsps(mac, base, 0).
dsps(dynamic_mac, byAsset, 0).
dsps(dynamic_mac, byComponent, 0).
dsps(dynamic_mac, base, 0).
dsps(zero_trust_logger, base, 0).
dsps(some_logging, base, 0).
dsps(no_logging, base, 0).

% LUTRAM utilization (Vivado defaults)
lutram(zero_trust, byAsset, 0).
lutram(zero_trust, byComponent, 64).
lutram(zero_trust, base, 0).
lutram(mac, byAsset, 0).
lutram(mac, byComponent, 0).
lutram(mac, base, 0).
lutram(dynamic_mac, byAsset, 0).
lutram(dynamic_mac, byComponent, 0).
lutram(dynamic_mac, base, 0).
lutram(zero_trust_logger, base, 0).
lutram(some_logging, base, 0).
lutram(no_logging, base, 0).

% BRAM utilization (Vivado defaults)
bram(zero_trust, byAsset, 0).
bram(zero_trust, byComponent, 0).
bram(zero_trust, base, 0).
bram(mac, byAsset, 0).
bram(mac, byComponent, 0).
bram(mac, base, 0).
bram(dynamic_mac, byAsset, 0).
bram(dynamic_mac, byComponent, 0).
bram(dynamic_mac, base, 0).
bram(zero_trust_logger, base, 2).
bram(some_logging, base, 1).
bram(no_logging, base, 0).

% BUFG utilization (Vivado defaults)
bufg(zero_trust, byAsset, 0).
bufg(zero_trust, byComponent, 0).
bufg(zero_trust, base, 0).
bufg(mac, byAsset, 0).
bufg(mac, byComponent, 0).
bufg(mac, base, 0).
bufg(dynamic_mac, byAsset, 0).
bufg(dynamic_mac, byComponent, 0).
bufg(dynamic_mac, base, 0).
bufg(zero_trust_logger, base, 0).
bufg(some_logging, base, 0).
bufg(no_logging, base, 0).

% Latency costs (Vivado defaults)
latency_cost(zero_trust, 3).
latency_cost(mac, 4).
latency_cost(dynamic_mac, 6).
latency_cost(zero_trust_logger, 2).
latency_cost(some_logging, 1).
latency_cost(no_logging, 1).

% Additive risk model: protection scores for opt_redundancy_generic_enc.lp
% security_protect_val(Feature, Score): cardinal reduction in residual risk
% log_protect_val(Feature, Score):      forensic deterrence reduction
security_protect_val(zero_trust, 8).
security_protect_val(mac, 4).
security_protect_val(dynamic_mac, 6).
log_protect_val(zero_trust_logger, 3).
log_protect_val(some_logging, 1).
log_protect_val(no_logging, 0).
