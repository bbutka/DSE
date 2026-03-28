int: n_components;
set of int: COMPONENTS = 1..n_components;
set of int: COMPONENT_OR_ZERO = 0..n_components;
int: n_security;
set of int: SECURITY = 1..n_security;
int: n_logging;
set of int: LOGGING = 1..n_logging;
int: n_groups;
set of int: GROUPS = 1..n_groups;
int: max_group_size;
set of int: POSITIONS = 1..max_group_size;

array[COMPONENTS] of string: component_name;
array[SECURITY] of string: security_name;
array[LOGGING] of string: logging_name;

int: mu;
int: omega;

array[COMPONENTS] of int: impact_read;
array[COMPONENTS] of int: impact_write;
array[COMPONENTS] of int: allowable_latency_read;
array[COMPONENTS] of int: allowable_latency_write;
array[COMPONENTS] of 0..n_groups: component_group;

array[GROUPS] of int: group_size;
array[GROUPS, POSITIONS] of COMPONENT_OR_ZERO: group_member;

array[SECURITY] of int: vulnerability;
array[SECURITY] of int: security_latency;
array[LOGGING] of int: logging_score;
array[LOGGING] of int: logging_latency;

array[SECURITY] of int: sec_luts_asset;
array[SECURITY] of int: sec_luts_component;
array[SECURITY] of int: sec_luts_base_once;
array[SECURITY] of int: sec_luts_base_per_use;
array[LOGGING] of int: log_luts_base_once;
array[LOGGING] of int: log_luts_base_per_use;

array[SECURITY] of int: sec_ffs_asset;
array[SECURITY] of int: sec_ffs_component;
array[SECURITY] of int: sec_ffs_base_once;
array[SECURITY] of int: sec_ffs_base_per_use;
array[LOGGING] of int: log_ffs_base_once;
array[LOGGING] of int: log_ffs_base_per_use;

array[SECURITY] of int: sec_dsps_asset;
array[SECURITY] of int: sec_dsps_component;
array[SECURITY] of int: sec_dsps_base_once;
array[SECURITY] of int: sec_dsps_base_per_use;
array[LOGGING] of int: log_dsps_base_once;
array[LOGGING] of int: log_dsps_base_per_use;

array[SECURITY] of int: sec_lutram_asset;
array[SECURITY] of int: sec_lutram_component;
array[SECURITY] of int: sec_lutram_base_once;
array[SECURITY] of int: sec_lutram_base_per_use;
array[LOGGING] of int: log_lutram_base_once;
array[LOGGING] of int: log_lutram_base_per_use;

array[SECURITY] of int: sec_bufg_asset;
array[SECURITY] of int: sec_bufg_component;
array[SECURITY] of int: sec_bufg_base_once;
array[SECURITY] of int: sec_bufg_base_per_use;
array[LOGGING] of int: log_bufg_base_once;
array[LOGGING] of int: log_bufg_base_per_use;

array[SECURITY] of int: sec_bram_asset;
array[SECURITY] of int: sec_bram_component;
array[SECURITY] of int: sec_bram_base_once;
array[SECURITY] of int: sec_bram_base_per_use;
array[LOGGING] of int: log_bram_base_once;
array[LOGGING] of int: log_bram_base_per_use;

array[SECURITY] of int: sec_power_asset;
array[SECURITY] of int: sec_power_component;
array[SECURITY] of int: sec_power_base_once;
array[SECURITY] of int: sec_power_base_per_use;
array[LOGGING] of int: log_power_base_once;
array[LOGGING] of int: log_power_base_per_use;

int: max_power;
int: max_luts;
int: max_ffs;
int: max_dsps;
int: max_lutram;
int: max_bufg;
int: max_bram;
int: max_asset_risk;

var SECURITY: sec_choice[COMPONENTS];
var LOGGING: log_choice[COMPONENTS];

array[SECURITY] of var 0..n_components: sec_use_count;
array[LOGGING] of var 0..n_components: log_use_count;

constraint forall(s in SECURITY)(
    sec_use_count[s] = sum(c in COMPONENTS)(bool2int(sec_choice[c] = s))
);
constraint forall(l in LOGGING)(
    log_use_count[l] = sum(c in COMPONENTS)(bool2int(log_choice[c] = l))
);

array[COMPONENTS] of var 0..10000: original_prob;
array[COMPONENTS] of var 0..1000: original_prob_normalized;
array[COMPONENT_OR_ZERO] of var 0..1000: original_prob_normalized_ext;

constraint original_prob_normalized_ext[0] = 0;
constraint forall(c in COMPONENTS)(
    original_prob[c] = vulnerability[sec_choice[c]] * logging_score[log_choice[c]] /\
    original_prob_normalized[c] = ((original_prob[c] - mu) * 1000) div (omega - mu) /\
    original_prob_normalized_ext[c] = original_prob_normalized[c]
);

array[COMPONENTS] of var 0..100: latency_total;
constraint forall(c in COMPONENTS)(
    latency_total[c] = security_latency[sec_choice[c]] + logging_latency[log_choice[c]]
);
constraint forall(c in COMPONENTS)(
    latency_total[c] <= allowable_latency_read[c] /\
    latency_total[c] <= allowable_latency_write[c]
);

array[COMPONENTS] of var 0..100000: original_register_risk_read;
array[COMPONENTS] of var 0..100000: original_register_risk_write;
constraint forall(c in COMPONENTS)(
    original_register_risk_read[c] = impact_read[c] * vulnerability[sec_choice[c]] * logging_score[log_choice[c]] div 10 /\
    original_register_risk_write[c] = impact_write[c] * vulnerability[sec_choice[c]] * logging_score[log_choice[c]] div 10
);

array[GROUPS, POSITIONS] of var 0..1000: partial_norm;
array[GROUPS] of var 0..1000: combined_prob_norm;
array[GROUPS] of var 0..2000: group_prob_denorm;

constraint forall(g in GROUPS)(
    if group_size[g] >= 1 then
        partial_norm[g, 1] = original_prob_normalized_ext[group_member[g, 1]]
    else
        partial_norm[g, 1] = 0
    endif
);

constraint forall(g in GROUPS, p in 2..max_group_size)(
    if p <= group_size[g] then
        partial_norm[g, p] = (partial_norm[g, p - 1] * original_prob_normalized_ext[group_member[g, p]]) div 1000
    else
        partial_norm[g, p] = partial_norm[g, p - 1]
    endif
);

constraint forall(g in GROUPS)(
    combined_prob_norm[g] = partial_norm[g, max_group_size] /\
    group_prob_denorm[g] = ((combined_prob_norm[g] * (omega - mu)) div 1000) + mu * 10
);

array[COMPONENTS] of var 0..100000: new_risk_read;
array[COMPONENTS] of var 0..100000: new_risk_write;

constraint forall(c in COMPONENTS)(
    if component_group[c] > 0 then
        new_risk_read[c] = impact_read[c] * group_prob_denorm[component_group[c]] div 100 /\
        new_risk_write[c] = impact_write[c] * group_prob_denorm[component_group[c]] div 100
    else
        new_risk_read[c] = original_register_risk_read[c] /\
        new_risk_write[c] = original_register_risk_write[c]
    endif
);

constraint forall(c in COMPONENTS)(
    new_risk_read[c] <= max_asset_risk /\
    new_risk_write[c] <= max_asset_risk
);

function var int: total_asset_resource(array[SECURITY] of int: asset_costs) =
    sum(c in COMPONENTS)(asset_costs[sec_choice[c]]);

function var int: total_component_resource(array[SECURITY] of int: component_costs) =
    sum(c in COMPONENTS)(component_costs[sec_choice[c]]);

function var int: total_security_base_resource(
    array[SECURITY] of int: base_once_costs,
    array[SECURITY] of int: base_per_use_costs
) =
    sum(s in SECURITY)((if sec_use_count[s] > 0 then base_once_costs[s] else 0 endif) + base_per_use_costs[s] * sec_use_count[s]);

function var int: total_logging_base_resource(
    array[LOGGING] of int: base_once_costs,
    array[LOGGING] of int: base_per_use_costs
) =
    sum(l in LOGGING)((if log_use_count[l] > 0 then base_once_costs[l] else 0 endif) + base_per_use_costs[l] * log_use_count[l]);

var int: total_luts_used = total_asset_resource(sec_luts_asset) + total_component_resource(sec_luts_component)
    + total_security_base_resource(sec_luts_base_once, sec_luts_base_per_use)
    + total_logging_base_resource(log_luts_base_once, log_luts_base_per_use);
var int: total_ffs_used = total_asset_resource(sec_ffs_asset) + total_component_resource(sec_ffs_component)
    + total_security_base_resource(sec_ffs_base_once, sec_ffs_base_per_use)
    + total_logging_base_resource(log_ffs_base_once, log_ffs_base_per_use);
var int: total_dsps_used = total_asset_resource(sec_dsps_asset) + total_component_resource(sec_dsps_component)
    + total_security_base_resource(sec_dsps_base_once, sec_dsps_base_per_use)
    + total_logging_base_resource(log_dsps_base_once, log_dsps_base_per_use);
var int: total_lutram_used = total_asset_resource(sec_lutram_asset) + total_component_resource(sec_lutram_component)
    + total_security_base_resource(sec_lutram_base_once, sec_lutram_base_per_use)
    + total_logging_base_resource(log_lutram_base_once, log_lutram_base_per_use);
var int: total_bufg_used = total_asset_resource(sec_bufg_asset) + total_component_resource(sec_bufg_component)
    + total_security_base_resource(sec_bufg_base_once, sec_bufg_base_per_use)
    + total_logging_base_resource(log_bufg_base_once, log_bufg_base_per_use);
var int: total_bram_used = total_asset_resource(sec_bram_asset) + total_component_resource(sec_bram_component)
    + total_security_base_resource(sec_bram_base_once, sec_bram_base_per_use)
    + total_logging_base_resource(log_bram_base_once, log_bram_base_per_use);
var int: total_power_used = total_asset_resource(sec_power_asset) + total_component_resource(sec_power_component)
    + total_security_base_resource(sec_power_base_once, sec_power_base_per_use)
    + total_logging_base_resource(log_power_base_once, log_power_base_per_use);

constraint total_luts_used <= max_luts;
constraint total_ffs_used <= max_ffs;
constraint total_dsps_used <= max_dsps;
constraint total_lutram_used <= max_lutram;
constraint total_bufg_used <= max_bufg;
constraint total_bram_used <= max_bram;
constraint total_power_used <= max_power;

var int: total_action_risk = sum(c in COMPONENTS)(new_risk_read[c] + new_risk_write[c]);
var int: total_max_asset_risk = sum(c in COMPONENTS)(max(new_risk_read[c], new_risk_write[c]));

solve minimize total_action_risk;

output
[
    "objective_total_action_risk=", show(total_action_risk), "\n",
    "reported_total_max_asset_risk=", show(total_max_asset_risk), "\n",
    "total_luts_used=", show(total_luts_used), "\n",
    "total_ffs_used=", show(total_ffs_used), "\n",
    "total_dsps_used=", show(total_dsps_used), "\n",
    "total_lutram_used=", show(total_lutram_used), "\n",
    "total_bram_used=", show(total_bram_used), "\n",
    "total_power_used=", show(total_power_used), "\n",
    "selected_features:\n"
] ++
[
    "  " ++ component_name[c] ++ " = " ++ security_name[sec_choice[c]] ++ " + " ++ logging_name[log_choice[c]]
    ++ " | risk(read/write)=" ++ show(new_risk_read[c]) ++ "/" ++ show(new_risk_write[c])
    ++ " | latency=" ++ show(latency_total[c]) ++ "\n"
    | c in COMPONENTS
] ++
[
    "group_probabilities:\n"
] ++
[
    "  g" ++ show(g) ++ " combined_prob_norm=" ++ show(combined_prob_norm[g]) ++ " denorm=" ++ show(group_prob_denorm[g]) ++ "\n"
    | g in GROUPS
];
