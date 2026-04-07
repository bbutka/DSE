# Pixhawk 6X Modeling Plan

Date: April 7, 2026

## Scope

This plan defines a documentation-faithful Pixhawk 6X topology for `DSE_Core`
using two related models:

1. `make_pixhawk6x_platform()`
2. `make_pixhawk6x_uav_network()`

The platform model captures only documented board facts. The UAV model layers
vehicle integration choices on top of that base.

## Freeze Notes

- Use `io_mcu` as the implementation identifier.
  PX4 and Holybro documentation disagree on the exact IO MCU silicon.
- Do not model the Rev 8 IMU set as manufacturer-diverse.
  The documented Rev 8 hardware is `3x ICM-45686`, so the IMU group is a
  same-silicon triple-redundant set with separate buses and independent power
  control.
- Treat power redundancy and NFC/debug exposure as documented refinements, not
  initial blocking requirements for implementation.

## Documentation Sources

The current model is based primarily on:

- PX4 Pixhawk 6X documentation
- Holybro Pixhawk 6X documentation
- ArduPilot Pixhawk 6X page:
  [common-holybro-pixhawk6X.rst](https://github.com/ArduPilot/ardupilot_wiki/blob/master/common/source/docs/common-holybro-pixhawk6X.rst)

Additional source notes incorporated from the ArduPilot page:

- `SERIAL1 -> UART7 (Telem1)`
- `SERIAL2 -> UART5 (Telem2)`
- `SERIAL3 -> USART1 (GPS1)`
- `SERIAL4 -> UART8 (GPS2)`
- `SERIAL5 -> USART2 (Telem3)`
- `SERIAL6 -> UART4 (User)`
- `SERIAL7 -> USART3 (Debug)`
- external RC can be attached through a true UART such as `SERIAL6 (UART4)`
- `NFC_GPIO` is a documented external GPIO surface

## Platform Model

### Documented components

- `fmu_h753`
- `io_mcu`
- `imu_1`
- `imu_2`
- `imu_3`
- `baro_1`
- `baro_2`
- `mag`
- `se050`
- `ps_fmu`

### Infrastructure / ports

- `imu_bus_1`
- `imu_bus_2`
- `imu_bus_3`
- `baro_bus_1`
- `baro_bus_2`
- `mag_bus`
- `gps1_port`
- `gps2_port`
- `telem1_port`
- `telem2_port`
- `telem3_port`
- `uart4_i2c_port`
- `eth_port`
- `spi5_ext`
- `can1`
- `can2`
- `px4io_link`

### Platform redundancy

- `imu_group = {imu_1, imu_2, imu_3}`
- `baro_group = {baro_1, baro_2}`

Documented common-cause note:
- the IMU set uses separate buses and independent power control, but still
  shares a temperature-controlled IMU board, which is a plausible common-cause
  thermal fault domain

### Platform services

- `attitude_sensor_svc`
- `altitude_sensor_svc`
- `mag_sensor_svc`
- `crypto_svc`
- `io_failsafe_svc`

### Platform capabilities

- `flight_stabilization_base`
- `failsafe_io`
- `crypto_anchor`

## UAV Overlay

### Added external components

- `gps_1`
- `gps_2`
- `telem_radio`
- `ground_station`
- `rc_receiver`
- `esc_bus_1`
- `esc_bus_2`
- `companion`
- `camera`
- `flash_fram`

### Overlay assumptions

These are vehicle integration choices, not Pixhawk 6X board facts:

- telemetry radio is attached to `telem1_port`
- two GPS receivers are attached to `gps1_port` and `gps2_port`
- dual CAN is used for redundant ESC command paths
- companion compute is attached through Ethernet
- camera is attached behind the companion computer
- FRAM/logging storage is attached to the external SPI bus
- the current baseline keeps `rc_receiver` on the `px4io_link` path for an
  independent failsafe-oriented model, even though the ArduPilot docs also
  support UART-based RC attachment through `UART4`

### Overlay redundancy

- `imu_group`
- `baro_group`
- `gps_group = {gps_1, gps_2}`
- `motor_bus_group = {esc_bus_1, esc_bus_2}`

### Overlay services

- `attitude_svc`
- `altitude_svc`
- `navigation_svc`
- `motor_svc`
- `comms_svc`
- `failsafe_svc`
- `crypto_svc`
- `payload_svc`
- `logging_svc`

### Overlay capabilities

- `flight_control`
- `navigation`
- `ground_comms`
- `rc_override`
- `surveillance`
- `crypto_ops`
- `logging`

## Asset Model

Explicit assets should be used for:

- IMUs: input
- barometers: input
- mag: input
- GPS units: input
- telemetry radio: bidirectional
- ESC buses: output
- companion Ethernet endpoint: bidirectional
- camera: input
- SE050 control path: bidirectional
- logging storage: bidirectional

## ZTA Candidates

Initial implementation priority:

- `pep_telem1`
- `pep_eth`
- `pep_can1`
- `pep_can2`
- `pep_gps2`
- `pep_px4io`
- `pep_se050`
- `ps_fmu`

Deferred, documented-only candidates:

- `pep_gps1`
- `pep_uart4_i2c`

Documented but not yet modeled explicitly:

- `USART3` debug port
- `NFC_GPIO`
- UART-based RC variant through `uart4_i2c_port`

## Expected Findings

- IMU redundancy is structurally strong due to separate buses and independent
  power control
- barometer redundancy is genuine and should not collapse to a fake shared-bus
  SPOF
- GPS redundancy is genuine if both external GPS receivers are present
- dual CAN can remove a motor-command SPOF when both buses are populated
- `se050` is a crypto SPOF
- `fmu_h753` remains the primary concentration point for mission capabilities
- `telem_radio -> telem1_port -> fmu_h753` is the dominant documented external
  ingress path
- `companion -> eth_port -> fmu_h753` is a high-value attack path in the UAV
  overlay

## Implementation Order

1. Add `make_pixhawk6x_platform()` to `dse_tool/core/asp_generator.py`
2. Add `make_pixhawk6x_uav_network()` to `dse_tool/core/asp_generator.py`
3. Register both in `dse_tool/gui/network_editor.py`
4. Add topology regression tests
5. Add targeted Phase 1 and end-to-end pipeline validation for the UAV overlay
6. Export generated `.lp` facts and capture a checked-in golden baseline fixture
