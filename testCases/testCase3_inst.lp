%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% File: testCase3_inst.lp
% Purpose: Multi-processor embedded SoC topology.
%
%  Architecture:
%    [jtag] --jtag--> [cpu0] --axi--> [axi_bus] --axi--> [ram]
%    [jtag] --jtag--> [cpu1] --axi-->     |      --axi--> [flash]
%                                          |      --apb--> [peripheral0]
%
%  Trust Zones:
%    secure_zone   : cpu0, cpu1, axi_bus, ram, flash
%    untrusted_zone: peripheral0
%    external_zone : jtag
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% --- Component declarations (used by init_enc.lp) ---
component(cpu0).
component(cpu1).
component(axi_bus).
component(ram).
component(flash).
component(peripheral0).
component(jtag).

% --- Typed directed connections: link(Src, Dst, Protocol) ---
link(cpu0,        axi_bus,     axi).
link(cpu1,        axi_bus,     axi).
link(axi_bus,     ram,         axi).
link(axi_bus,     flash,       axi).
link(axi_bus,     peripheral0, apb).
link(jtag,        cpu0,        jtag).
link(jtag,        cpu1,        jtag).

% --- Trust domains ---
node_zone(cpu0,        secure_zone).
node_zone(cpu1,        secure_zone).
node_zone(axi_bus,     secure_zone).
node_zone(ram,         secure_zone).
node_zone(flash,       secure_zone).
node_zone(peripheral0, untrusted_zone).
node_zone(jtag,        external_zone).

% --- Node type classification ---
node_type(cpu0,        processor).
node_type(cpu1,        processor).
node_type(axi_bus,     bus).
node_type(ram,         memory).
node_type(flash,       memory).
node_type(peripheral0, peripheral).
node_type(jtag,        debug_port).

% --- Assets per component ---
asset(cpu0,        firmware_key).   % Cryptographic key stored in CPU0
asset(cpu0,        boot_cfg).       % Boot configuration register
asset(cpu1,        task_state).     % Runtime task state register
asset(ram,         dram_data).      % Data in DRAM
asset(flash,       flash_image).    % Firmware image in flash
asset(peripheral0, periph_cfg).     % Peripheral configuration register

% --- Impact values (1=negligible .. 9=critical) ---
impact(firmware_key, 9).   % Crypto key compromise = system-wide breach
impact(boot_cfg,     7).   % Tampered boot = persistent compromise
impact(task_state,   5).   % Task state leak = privilege escalation
impact(dram_data,    6).   % DRAM data = sensitive runtime data
impact(flash_image,  8).   % Firmware tamper = permanent backdoor
impact(periph_cfg,   3).   % Peripheral config = limited blast

% --- Critical nodes: system stops working if these fail ---
critical_node(cpu0).
critical_node(cpu1).
critical_node(axi_bus).
critical_node(flash).
