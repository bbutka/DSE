%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% By: Abigail Butka
% File: Security Features Instantiation
% Last Edited: 6/26/2025
% Purpose: Define all security and logging features, and
%			their resource/power utilizations
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


% Define Security and Logging Features ---------------------

% Define Security Features
security_feature(zero_trust).  % very secure, high cost
security_feature(mac).         % low security, low cost
security_feature(dynamic_mac). % medium security, medium cost

% Define Logging Features
logging_feature(zero_trust_logger).
logging_feature(some_logging).
logging_feature(no_logging).

% End Definition -------------------------------------------




% Define Power Costs ---------------------------------------

power_cost(mac, byAsset, 1).                   % Each asset with mac costs 1mW
power_cost(mac, byComponent, 2).               % Each component with mac costs 2mW

power_cost(dynamic_mac, byAsset, 1).           % Each asset with dynamic mac costs 3mW
power_cost(dynamic_mac, byComponent, 2).       % Each component with dynamic mac costs 2mW
power_cost(dynamic_mac, base, 2).              % Base 2mW dynamic_mac policy server and MicroBlaze

power_cost(zero_trust, byAsset, 1).            % Each asset with ZTA costs 3mW
power_cost(zero_trust, byComponent, 2).        % Each component with ZTA costs 2mW
power_cost(zero_trust, base, 2).               % Base 2mW for ZTA policy server and MicroBlaze

power_cost(some_logging, base, 72).            % 72 Estimate, no implementation
power_cost(zero_trust_logger, base, 717).      % 717mW 

% End Define Power Costs -----------------------------------




% Define Risk Calculation Values ---------------------------

% Define Vulnerability Values
                                            % Vulnerability is between 1 (10) and 5 (50), scaled because POTASSCO ONLY SUPPORTS INTEGER REPRESENTATION
vulnerability(zero_trust, 10).
vulnerability(mac, 30).
vulnerability(dynamic_mac, 20).

% Define Logging Values for Risk Calculations --------------
											%(Logging is between 5 (0.5) and 20 (2), POTASSCO ONLY SUPPORTS INTEGER REPRESENTATION
logging(zero_trust_logger, 5).
logging(some_logging, 10).
logging(no_logging, 20).

% End Define Risk Calculation Values -----------------------




% Define Resource Utilization for Security Features -------------

% Define LUT utilization costs
luts(mac, byAsset, 51).                  % Each asset with mac costs 51 LUTs
luts(mac, byComponent, 234).             % Each asset with mac costs 51 LUTs

luts(dynamic_mac, byAsset, 51).          % Base 51 LUTs for dynamic_mac per asset
luts(dynamic_mac, byComponent, 234).     % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
luts(dynamic_mac, base, 1985).           % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze

luts(zero_trust, byAsset, 51).           % Base 51 LUTs for dynamic_mac per asset
luts(zero_trust, byComponent, 234).      % Base 1985 LUTs for ZTA policy server and MicroBlaze
luts(zero_trust, base, 1985).            % Base 1985 LUTs for ZTA policy server and MicroBlaze

luts(some_logging, base, 3135).          % Cost of autoencoder only. 
luts(zero_trust_logger, base, 31354).    % Cost of autoencoder only. 


% Define FF utilization costs
ffs(mac, byAsset, 32).                   % Each asset with mac costs 51 LUTs
ffs(mac, byComponent, 292).              % Each asset with mac costs 51 LUTs

ffs(dynamic_mac, byAsset, 32).           % Base 51 LUTs for dynamic_mac per asset
ffs(dynamic_mac, byComponent, 292).      % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
ffs(dynamic_mac, base, 1612).            % Base 1378 FFs for dynamic_mac policy server and MicroBlaze

ffs(zero_trust, byAsset, 32).            % Base 51 LUTs for dynamic_mac per asset
ffs(zero_trust, byComponent, 292).       % Base 1985 LUTs for ZTA policy server and MicroBlaze
ffs(zero_trust, base, 1612).             % zero-trust autoencoder(25020) and policy server+MicroBlaze(1612)

ffs(some_logging, base, 2502).           % Cost of autoencoder only. Estimate!
ffs(zero_trust_logger, base, 25020).     % Cost of autoencoder only. 



% Define DSP utilization costs

dsps(mac, byAsset, 0).                   % Each asset with mac costs 51 LUTs
dsps(mac, byComponent, 0).               % Each asset with mac costs 51 LUTs

dsps(dynamic_mac, byAsset, 0).           % Base 51 LUTs for dynamic_mac per asset
dsps(dynamic_mac, byComponent, 0).       % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
dsps(dynamic_mac, base, 0).              % Base 1378 FFs for dynamic_mac policy server and MicroBlaze

dsps(zero_trust, byAsset, 0).            % Base 51 LUTs for dynamic_mac per asset
dsps(zero_trust, byComponent, 0).        % Base 1985 LUTs for ZTA policy server and MicroBlaze
dsps(zero_trust, base, 0).               % zero-trust autoencoder(25020) and policy server+MicroBlaze(1612)

dsps(some_logging, base, 22).            % Cost of autoencoder only. Estimate! Assuming  
dsps(zero_trust_logger, base, 220).      % Cost of autoencoder only. 




% Define LUTRAM utilization costs

lutram(mac, byAsset, 0).                 % Each asset with mac costs 51 LUTs
lutram(mac, byComponent, 0).             % Each asset with mac costs 51 LUTs

lutram(dynamic_mac, byAsset, 0).         % Base 51 LUTs for dynamic_mac per asset
lutram(dynamic_mac, byComponent, 0).     % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
lutram(dynamic_mac, base, 201).          % Base 1378 FFs for dynamic_mac policy server and MicroBlaze

lutram(zero_trust, byAsset, 0).          % Base 51 LUTs for dynamic_mac per asset
lutram(zero_trust, byComponent, 0).      % Base 1985 LUTs for ZTA policy server and MicroBlaze
lutram(zero_trust, base, 201).           % zero-trust autoencoder(25020) and policy server+MicroBlaze(1612)

lutram(some_logging, base, 2).           % Cost of autoencoder only. Estimate!
lutram(zero_trust_logger, base, 154).    % Cost of autoencoder only. 



% Define BUFG utilization costs

bufg(mac, byAsset, 0).                   % Each asset with mac costs 51 LUTs
bufg(mac, byComponent, 0).               % Each asset with mac costs 51 LUTs

bufg(dynamic_mac, byAsset, 0).           % Base 51 LUTs for dynamic_mac per asset
bufg(dynamic_mac, byComponent, 0).       % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
bufg(dynamic_mac, base, 0).              % Base 1378 FFs for dynamic_mac policy server and MicroBlaze

bufg(zero_trust, byAsset, 0).            % Base 51 LUTs for dynamic_mac per asset
bufg(zero_trust, byComponent, 0).        % Base 1985 LUTs for ZTA policy server and MicroBlaze
bufg(zero_trust, base, 0).               % zero-trust autoencoder(25020) and policy server+MicroBlaze(1612)

bufg(some_logging, base, 0).             % Cost of autoencoder only. 
bufg(zero_trust_logger, base, 0).        % Cost of autoencoder only. 


% Define BRAM utilization costs
							
bram(mac, byAsset, 0).                   % Each asset with mac costs 51 LUTs
bram(mac, byComponent, 0).               % Each asset with mac costs 51 LUTs

bram(dynamic_mac, byAsset, 0).           % Base 51 LUTs for dynamic_mac per asset
bram(dynamic_mac, byComponent, 0).       % Base 1985 LUTs for dynamic_mac policy server and MicroBlaze
bram(dynamic_mac, base, 8).              % Base 1378 FFs for dynamic_mac policy server and MicroBlaze

bram(zero_trust, byAsset, 0).            % Base 51 LUTs for dynamic_mac per asset
bram(zero_trust, byComponent, 0).        % Base 1985 LUTs for ZTA policy server and MicroBlaze
bram(zero_trust, base, 8).               % zero-trust autoencoder(25020) and policy server+MicroBlaze(1612)

bram(some_logging, base, 2).             % Cost of autoencoder only. Estimate!
bram(zero_trust_logger, base, 18).       % Cost of autoencoder only. 
										
% End Define Resource Utilization for All Features ---------




% Define Latency Costs -------------------------------------

% Measured in clock cycles

% For Security Features
latency_cost(mac, 3).
latency_cost(dynamic_mac, 7).
latency_cost(zero_trust, 7).


% For Logging Features
latency_cost(zero_trust_logger, 22).
latency_cost(some_logging, 4).
latency_cost(no_logging, 0).

% End Define Latency Costs ---------------------------------