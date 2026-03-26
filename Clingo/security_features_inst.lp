%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Security Features Instantiation
% Last Edited: 6/24/2025
% Purpose: Define all security and logging features, and
%			their resource/power utilizations
% Missing: 
%		- Real values for DSP, LUTRAM, BUFG
%		- Base and by asset power utilizations
%		- Separate resource utilizations into security/logging
%		- Accurate resource utilizations. Ex. Should a 
%			component with 20 assets have the same
%			utilization as 20 components with 1 asset?
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Define Security and Logging Features ---------------------

% Define Security Features
security_feature(zero_trust).  % very secure, high cost
security_feature(mac).         % low security, low cost
security_feature(dynamic_mac). % medium security, medium cost

% Define Logging Features
logging_feature(zero_trust_logger ; some_logging ; no_logging).
logging_feature(zero_trust_logger).
logging_feature(some_logging).
logging_feature(no_logging).

% End Definition -------------------------------------------




% Define Power Costs ---------------------------------------

% For Security Features
power_cost(zero_trust, 3).
power_cost(mac, 1).
power_cost(dynamic_mac, 2).

% For Logging Features
power_cost(zero_trust_logger, 2).
power_cost(some_logging, 1).
power_cost(no_logging, 0).

% End Define Power Costs -----------------------------------




% Define Risk Calculation Values ---------------------------

% Define Vulnerability Values 
vulnerability(zero_trust, 1).
vulnerability(mac, 3).
vulnerability(dynamic_mac, 2).

% Define Logging Values for Risk Calculations --------------
											%(Logging is between 5 (0.5) and 20 (2), POTASSCO ONLY SUPPORTS INTEGER REPRESENTATION
logging(zero_trust_logger, 5).
logging(some_logging, 10).
logging(no_logging, 20).

% End Define Risk Calculation Values -----------------------




% Define Resource Utilization for All Features -------------

% Define LUT utilization costs
luts(mac, 51).                          % Each asset with mac costs 51 LUTs
luts(dynamic_mac_base, 1568).           % Base 40 LUTs for dynamic_mac policy server and MicroBlaze
luts(dynamic_mac, 51).                  % Each asset with dynamic_mac costs 51 LUTs
luts(zero_trust_base, 32922).           % Base 31354 LUTs for zero-trust autoencoder(31354) and policy server+MicroBlaze(1568)
luts(zero_trust, 51).                   % Each asset with zero-trust costs 51 LUTs

% Define FF utilization costs
ffs(mac, 64).                           % Each asset with mac costs 64 FFs
ffs(dynamic_mac_base, 1378).            % Base 1378 FFs for dynamic_mac policy server and MicroBlaze
ffs(dynamic_mac, 64).                   % Each asset with dynamic_mac costs 64 FFs
ffs(zero_trust_base, 26398).            % Base 25020 FFs for zero-trust autoencoder(25020) and policy server+MicroBlaze(1378)
ffs(zero_trust, 64).                    % Each asset with zero-trust costs 64 FFs

% Define DSP utilization costs
dsps(mac, 64).                           % Each asset with mac costs 64 FFs
dsps(dynamic_mac_base, 1378).            % Base 1378 FFs for dynamic_mac policy server and MicroBlaze
dsps(dynamic_mac, 64).                   % Each asset with dynamic_mac costs 64 FFs
dsps(zero_trust_base, 26398).            % Base 25020 FFs for zero-trust autoencoder(25020) and policy server+MicroBlaze(1378)
dsps(zero_trust, 64).                    % Each asset with zero-trust costs 64 FFs

% Define LUTRAM utilization costs
lutram(mac, 64).                        % Each asset with mac costs 64 FFs
lutram(dynamic_mac_base, 1378).         % Base 1378 FFs for dynamic_mac policy server and MicroBlaze
lutram(dynamic_mac, 64).                % Each asset with dynamic_mac costs 64 FFs
lutram(zero_trust_base, 26398).         % Base 25020 FFs for zero-trust autoencoder(25020) and policy server+MicroBlaze(1378)
lutram(zero_trust, 64).                 % Each asset with zero-trust costs 64 FFs

% Define BUFG utilization costs
bufg(mac, 64).                          % Each asset with mac costs 64 FFs
bufg(dynamic_mac_base, 1378).           % Base 1378 FFs for dynamic_mac policy server and MicroBlaze
bufg(dynamic_mac, 64).                  % Each asset with dynamic_mac costs 64 FFs
bufg(zero_trust_base, 26398).           % Base 25020 FFs for zero-trust autoencoder(25020) and policy server+MicroBlaze(1378)
bufg(zero_trust, 64).                   % Each asset with zero-trust costs 64 FFs

% End Define Resource Utilization for All Features ---------




% Define Latency Costs -------------------------------------

% Measured in clock cycles

% For Security Features
latency_cost(mac, 3).
latency_cost(dynamic_mac, 3).
latency_cost(zero_trust, 3).


% For Logging Features
latency_cost(zero_trust_logger, 22).
latency_cost(some_logging, 4).
latency_cost(no_logging, 0).

% End Define Latency Costs ---------------------------------