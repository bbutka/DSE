# Vivado Resource Catalog Guide

**Date:** 2026-03-28
**Purpose:** Document the Vivado-based resource calibration workflow and the planned transition to `ip_catalog/xilinx_ip_catalog.py` as the single source of truth for all resource estimates.

---

## Overview

The DSE tool uses two sources for hardware resource estimates:

| Source | Status | Use Case |
|--------|--------|----------|
| **Vivado-calibrated IP Catalog** (`ip_catalog/xilinx_ip_catalog.py`) | **Primary (future default)** | All Phase 1/2/3 resource estimates |
| **ASP encoding inline values** (`Clingo/security_features_inst.lp`) | Legacy | Currently hardcoded in LP files — will be replaced |

The long-term goal is to make `xilinx_ip_catalog.py` the **single source of truth** for all resource values, eliminating duplicate definitions and enabling Vivado-based calibration without touching ASP logic.

---

## Current IP Catalog Contents

### Security Features

| Feature | LUTs | FFs | LUTRAMs | BRAMs | DSPs | Power (mW) | Latency (cyc) | Fmax (MHz) |
|---------|------|-----|---------|-------|------|------------|---------------|------------|
| `mac` | 650 | 420 | 0 | 0 | 0 | 12.0 | 4 | 250 |
| `dynamic_mac` | 950 | 680 | 0 | 0 | 0 | 18.0 | 6 | 200 |
| `zero_trust` | 1200 | 850 | 64 | 0 | 0 | 24.0 | 3 | 200 |
| `zero_trust_logger` | 520 | 480 | 0 | 2 | 0 | 11.0 | 2 | 250 |
| `some_logging` | 180 | 220 | 0 | 1 | 0 | 4.0 | 1 | 300 |
| `no_logging` | 0 | 0 | 0 | 0 | 0 | 0.0 | 0 | — |
| `no_security` | 0 | 0 | 0 | 0 | 0 | 0.0 | 0 | — |
| `passthrough` | 0 | 0 | 0 | 0 | 0 | 0.0 | 0 | — |

### NoC / Interconnect Components

| Component | LUTs | FFs | Power (mW) | Latency (cyc) |
|-----------|------|-----|------------|---------------|
| `crossbar_4x4` | 280 | 350 | 6.0 | 2 |
| `crossbar_8x8` | 1100 | 1400 | 18.0 | 3 |
| `router_5port` | 520 | 640 | 9.0 | 3 |
| `router_8port` | 950 | 1180 | 16.0 | 4 |
| `axi_fabric` | 3200 | 4800 | 45.0 | 5 |

### Phase 2/3 Overhead Components

| Component | LUTs | FFs | Power (mW) | Latency (cyc) | Notes |
|-----------|------|-----|------------|---------------|-------|
| `fw_overhead` | 350 | 280 | 7.0 | 5 | Per firewall instance |
| `ps_overhead` | 500 | 400 | 9.0 | 8 | Policy server CPU |
| `monitor_overhead` | 200 | 300 | 5.0 | 1 | Runtime monitor FSM |
| `bus_bridge` | 120 | 180 | 3.0 | 2 | AXI-Lite bridge |
| `dma_engine` | 450 | 380 | 8.0 | 1 | AXI DMA descriptor table |

### Reference Crypto Primitives

| Component | LUTs | FFs | DSPs | Power (mW) | Latency (cyc) |
|-----------|------|-----|------|------------|---------------|
| `aes_128` | 1200 | 800 | 5 | 28.0 | 10 |
| `sha256` | 800 | 420 | 0 | 15.0 | 20 |

---

## Target Device

All estimates are for:

```
Part:     xc7z020clg400-1  (PYNQ-Z2)
LUTs:     53,200
FFs:      106,400
BRAM:     140  (18Kb tiles)
DSP:      220  (DSP48E1 slices)
LUTRAM:   17,400
CLK:      125 MHz (8 ns period)
```

---

## Calibration Workflow

### Step 1 — Build the Baseline Shell

1. Create a Vivado RTL project targeting `xc7z020clg400-1`
2. Add `feature_shell_baseline.v` from `vivado_calibration_sample/`
3. Run synthesis and implementation (Out-of-Context recommended)
4. Save post-implementation reports:
   - `baseline_util_post_route.rpt`
   - `baseline_power_post_route.rpt`

### Step 2 — Build the Feature Shell

1. Replace top module with `feature_shell_with_mac_like.v` (or real RTL)
2. Re-run synthesis and implementation
3. Save the same report types with feature-specific names

### Step 3 — Compute Delta (Feature Cost)

```
feature_cost = (shell + feature) - shell
```

Record LUT, FF, DSP, BRAM, and power deltas. This is the calibrated cost.

### Step 4 — Update the IP Catalog

Edit `ip_catalog/xilinx_ip_catalog.py` with the measured values:

```python
"my_feature": IPResourceEstimate(
    luts=<measured>,
    ffs=<measured>,
    brams=<measured>,
    dsps=<measured>,
    power_mw=<measured>,
    latency=<pipeline_depth>,
    fmax_mhz=<fmax>,
    notes="Vivado-calibrated (<vivado_version>, <part>). "
          "Source: <path_to_report>",
),
```

### Step 5 — Register Calibration Record (Optional)

For auditability, add a calibration record:

```python
add_calibration_measurement(
    feature_name="my_feature",
    luts=<measured>,
    ffs=<measured>,
    brams=<measured>,
    dsps=<measured>,
    power_mw=<measured>,
    source="vivado_measured",
    vivado_version="2024.1",
    notes="Delta from post-route reports",
)
```

---

## Using the Catalog Programmatically

### Quick Feature Estimate

```python
from ip_catalog.xilinx_ip_catalog import get_calibrated_estimate

est = get_calibrated_estimate("mac")
print(f"LUTs: {est.luts}, FFs: {est.ffs}, Power: {est.power_mw}mW")
```

### Sum Multiple Features

```python
from ip_catalog.xilinx_ip_catalog import IPResourceEstimate
from ip_catalog.xilinx_ip_catalog import get_calibrated_estimate

features = ["mac", "zero_trust", "some_logging"]
total = IPResourceEstimate()
for f in features:
    est = get_calibrated_estimate(f)
    total.luts += est.luts
    total.ffs += est.ffs
    total.power_mw += est.power_mw

print(f"Total: LUTs={total.luts}, FFs={total.ffs}, Power={total.power_mw}mW")
```

### Full tc9 Configuration Estimate

```bash
python vivado_resource_estimator.py --features mac,zero_trust,some_logging,no_logging
```

### Check Utilization Against Device

```python
from ip_catalog.xilinx_ip_catalog import utilization_percentage

util = utilization_percentage(luts=9385, ffs=8318, brams=4, dsps=0)
print(f"LUT: {util['lut_pct']:.1f}%")
print(f"FF:  {util['ff_pct']:.1f}%")
print(f"BRAM: {util['bram_pct']:.1f}%")
print(f"DSP:  {util['dsp_pct']:.1f}%")
```

---

## Transition Plan: Catalog as Default

### Current State

Currently, resource values are defined in **two places** that can drift:

1. `ip_catalog/xilinx_ip_catalog.py` — Python API with LUT/FF/power
2. `Clingo/security_features_inst.lp` — Inline ASP facts

### Target State

`xilinx_ip_catalog.py` becomes the **single source of truth**. The ASP encodings will **import from the catalog** rather than duplicating values.

### Migration Steps

| Step | Action | File(s) Affected |
|------|--------|-----------------|
| 1 | Add all missing Phase 2/3 overhead entries to catalog | `ip_catalog/xilinx_ip_catalog.py` |
| 2 | Update `get_calibrated_estimate()` to read from catalog for all feature names | `ip_catalog/xilinx_ip_catalog.py` |
| 3 | Add ASP export function to generate `security_features_inst.lp` from catalog | `ip_catalog/xilinx_ip_catalog.py` |
| 4 | Run export before each DSE run to regenerate LP facts | `dse_tool/core/asp_generator.py` or `runClingo_tc9.py` |
| 5 | Remove hardcoded values from `security_features_inst.lp` | `Clingo/security_features_inst.lp` |
| 6 | Update calibration workflow docs | This document |

### ASP Export Function (To Be Implemented)

```python
def export_security_facts_to_lp(filepath: str) -> None:
    """Export all IP_CATALOG security feature facts as a .lp file."""
    lines = [
        "% Auto-generated by xilinx_ip_catalog.py",
        "% Do not edit manually",
        "",
    ]
    for name, est in IP_CATALOG.items():
        lines.append(f"security_feature_resource({name}, lut, {est.luts}).")
        lines.append(f"security_feature_resource({name}, ff, {est.ffs}).")
        if est.power_mw:
            lines.append(f"security_feature_resource({name}, power, {est.power_mw}).")
        if est.latency:
            lines.append(f"security_feature_latency({name}, {est.latency}).")
    with open(filepath, "w") as f:
        f.write("\n".join(lines))
```

---

## Vivado Calibration Checklist

Before the catalog is finalized as the default, calibrate each of these features:

| Priority | Feature | Status | Measured LUTs | Measured FFs | Measured Power |
|----------|---------|--------|--------------|-------------|----------------|
| HIGH | `mac` | Pending | — | — | — |
| HIGH | `dynamic_mac` | Pending | — | — | — |
| HIGH | `zero_trust` | Pending | — | — | — |
| HIGH | `some_logging` | Pending | — | — | — |
| HIGH | `zero_trust_logger` | Pending | — | — | — |
| MEDIUM | `fw_overhead` | Pending | — | — | — |
| MEDIUM | `ps_overhead` | Pending | — | — | — |
| MEDIUM | `monitor_overhead` | Pending | — | — | — |
| LOW | `aes_128` | Pending | — | — | — |
| LOW | `sha256` | Pending | — | — | — |

---

## Validation Against Vivado

### tc9 Phase 1 Result (Current Calibration)

| Metric | IP Catalog (Phase 1 only) | Vivado Post-Impl | Delta |
|--------|--------------------------|-----------------|-------|
| LUTs | 8,930 | 9,385 | -455 (-4.9%) |
| FFs | 7,270 | 8,318 | -1,048 (-12.6%) |
| Power | 171 mW | 108 mW | +63 mW (+58%) |
| Risk | — | 361 | — |

**Observations:**
- LUT estimates are reasonably accurate (-4.9%)
- FF estimates underestimate by ~12% — should be inflated ~15%
- Power estimates significantly overestimate (+58%) — needs downward calibration

### With Phase 2/3 Overhead Added

| Metric | Catalog (P1+P2+P3) | Vivado | Delta |
|--------|-------------------|--------|-------|
| LUTs | 10,930 | 9,385 | +1,545 (+16.5%) |
| FFs | 9,430 | 8,318 | +1,112 (+13.4%) |
| Power | 214 mW | 108 mW | +106 mW (+98%) |

This suggests Phase 2/3 overhead estimates in the catalog are too conservative, OR the Vivado build did not include Phase 2/3 components.

---

## Files Reference

| File | Purpose |
|------|---------|
| `ip_catalog/xilinx_ip_catalog.py` | Primary catalog — all resource definitions |
| `vivado_resource_estimator.py` | CLI tool for generating estimates from catalog |
| `vivado_calibration_sample/` | Starter RTL and checklist for calibration builds |
| `Clingo/security_features_inst.lp` | ASP facts — **will be auto-generated from catalog** |
| `Clingo/opt_resource_enc.lp` | Resource constraint encoding (uses ASP facts) |

---

## Next Steps

1. **Run Vivado builds** for each HIGH priority feature in the calibration checklist
2. **Update `xilinx_ip_catalog.py`** with measured values
3. **Validate** the updated catalog against the tc9 Vivado build
4. **Implement ASP export function** to generate `.lp` facts from catalog
5. **Update `asp_generator.py`** to call export before DSE runs
6. **Remove duplicate values** from `security_features_inst.lp`

---

*Document created: 2026-03-28*
