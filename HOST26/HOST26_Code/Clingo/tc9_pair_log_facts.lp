% tc9_pair_log_facts.lp
%
% Pair-level fixed-point probabilities and log weights for tc9 Phase 1.
% These facts are generated for the original security/logging feature pairs
% using the supplied LUT pack's scaling convention:
%
%   prob_scale = 1_000_000
%   prob_scaled = round(((V*L) - mu) / (omega - mu) * prob_scale)
%   log_weight = round(ln(prob_scaled) * 1_000_000)
%
% This lets Clingo optimize with additive log weights and no chained
% multiplication during exploration.

prob_scale(1000000).
ln_scale(1000000).

pair_prob_scaled(dynamic_mac, no_logging, 384615).
pair_log_weight(dynamic_mac, no_logging, 12859998).

pair_prob_scaled(dynamic_mac, some_logging, 179487).
pair_log_weight(dynamic_mac, some_logging, 12097858).

pair_prob_scaled(dynamic_mac, zero_trust_logger, 76923).
pair_log_weight(dynamic_mac, zero_trust_logger, 11250560).

pair_prob_scaled(mac, no_logging, 589744).
pair_log_weight(mac, no_logging, 13287444).

pair_prob_scaled(mac, some_logging, 282051).
pair_log_weight(mac, some_logging, 12549843).

pair_prob_scaled(mac, zero_trust_logger, 128205).
pair_log_weight(mac, zero_trust_logger, 11761386).

pair_prob_scaled(zero_trust, no_logging, 179487).
pair_log_weight(zero_trust, no_logging, 12097858).

pair_prob_scaled(zero_trust, some_logging, 76923).
pair_log_weight(zero_trust, some_logging, 11250560).

pair_prob_scaled(zero_trust, zero_trust_logger, 25641).
pair_log_weight(zero_trust, zero_trust_logger, 10151948).
