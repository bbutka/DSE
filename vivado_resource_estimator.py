"""
vivado_resource_estimator.py
============================
Generate Vivado resource estimates for HOST26 tc9 security designs
using the existing xilinx_ip_catalog.py estimates.

Usage:
    python vivado_resource_estimator.py --design <design_file.lp>
    python vivado_resource_estimator.py --features mac,zero_trust,some_logging
    python vivado_resource_estimator.py --list-features
"""

import argparse
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from ip_catalog.xilinx_ip_catalog import (
    IP_CATALOG,
    NOC_CATALOG,
    TC9_NOC_MODEL,
    IPResourceEstimate,
    get_calibrated_estimate,
    utilization_percentage,
    TARGET_LUT, TARGET_FF, TARGET_BRAM, TARGET_DSP,
    TARGET_DEVICE,
)


def estimate_features(feature_list: list) -> dict:
    """Sum resource estimates for a list of security features."""
    total = IPResourceEstimate()
    breakdown = {}

    for feat in feature_list:
        est = get_calibrated_estimate(feat)
        breakdown[feat] = est
        total.luts += est.luts
        total.ffs += est.ffs
        total.lutrams += est.lutrams
        total.brams += est.brams
        total.dsps += est.dsps
        total.power_mw += est.power_mw
        total.latency = max(total.latency, est.latency)

    return {"total": total, "breakdown": breakdown}


def format_estimate(name: str, est: IPResourceEstimate, indent: int = 0) -> str:
    """Format a single resource estimate as a readable string."""
    pad = " " * indent
    lines = [
        f"{pad}{name}:",
        f"{pad}  LUTs:     {est.luts:,}",
        f"{pad}  FFs:      {est.ffs:,}",
        f"{pad}  LUTRAMs: {est.lutrams}",
        f"{pad}  BRAMs:   {est.brams}",
        f"{pad}  DSPs:    {est.dsps}",
        f"{pad}  Power:   {est.power_mw:.1f} mW",
        f"{pad}  Latency: {est.latency} cycles",
    ]
    if est.fmax_mhz:
        lines.append(f"{pad}  Fmax:    {est.fmax_mhz} MHz")
    if est.notes:
        lines.append(f"{pad}  Notes:   {est.notes}")
    return "\n".join(lines)


def print_estimates(features: list, include_breakdown: bool = True):
    """Print resource estimates to console."""
    result = estimate_features(features)

    print("=" * 60)
    print("VIVADO RESOURCE ESTIMATES (Post-Implementation)")
    print(f"Target Device: {TARGET_DEVICE}")
    print("=" * 60)

    # Add NoC overhead for tc9 designs
    noc_luts = TC9_NOC_MODEL.total_luts()
    noc_ffs = TC9_NOC_MODEL.total_ffs()
    noc_power = TC9_NOC_MODEL.total_power_mw()

    print("\n--- NoC Overhead (tc9 baseline) ---")
    print(f"  LUTs:    {noc_luts:,}")
    print(f"  FFs:     {noc_ffs:,}")
    print(f"  Power:   {noc_power:.1f} mW")

    if include_breakdown and result["breakdown"]:
        print("\n--- Per-Feature Breakdown ---")
        for feat_name, est in result["breakdown"].items():
            print(format_estimate(feat_name, est, indent=2))
            print()

    print("--- TOTAL ---")
    total = result["total"]
    grand_luts = total.luts + noc_luts
    grand_ffs = total.ffs + noc_ffs
    grand_power = total.power_mw + noc_power

    print(f"  LUTs:     {grand_luts:,}")
    print(f"  FFs:      {grand_ffs:,}")
    print(f"  LUTRAMs:  {total.lutrams}")
    print(f"  BRAMs:    {total.brams}")
    print(f"  DSPs:     {total.dsps}")
    print(f"  Power:    {grand_power:.1f} mW")

    print("\n--- Utilization on Target Device ---")
    util = utilization_percentage(grand_luts, grand_ffs, total.brams, total.dsps)
    print(f"  LUT:  {util['lut_pct']:.1f}%  ({grand_luts:,} / {TARGET_LUT:,})")
    print(f"  FF:   {util['ff_pct']:.1f}%  ({grand_ffs:,} / {TARGET_FF:,})")
    print(f"  BRAM: {util['bram_pct']:.1f}%  ({total.brams} / {TARGET_BRAM})")
    print(f"  DSP:  {util['dsp_pct']:.1f}%  ({total.dsps} / {TARGET_DSP})")


def list_available_features():
    """List all features in the IP catalog."""
    print("Available Security Features:")
    print("-" * 40)
    for name in sorted(IP_CATALOG.keys()):
        est = IP_CATALOG[name]
        print(f"  {name:<25} LUTs:{est.luts:>5}  FFs:{est.ffs:>5}")

    print("\nAvailable NoC Components:")
    print("-" * 40)
    for name in sorted(NOC_CATALOG.keys()):
        est = NOC_CATALOG[name]
        print(f"  {name:<25} LUTs:{est.luts:>5}  FFs:{est.ffs:>5}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Vivado resource estimates using IP catalog"
    )
    parser.add_argument(
        "--features", "-f",
        help="Comma-separated list of security features (e.g., mac,zero_trust,some_logging)"
    )
    parser.add_argument(
        "--list-features", "-l",
        action="store_true",
        help="List all available features and exit"
    )
    parser.add_argument(
        "--no-breakdown",
        action="store_true",
        help="Hide per-feature breakdown"
    )
    parser.add_argument(
        "--noc-only",
        action="store_true",
        help="Show only NoC baseline (tc9)"
    )

    args = parser.parse_args()

    if args.list_features:
        list_available_features()
        return

    if args.noc_only:
        noc_luts = TC9_NOC_MODEL.total_luts()
        noc_ffs = TC9_NOC_MODEL.total_ffs()
        noc_power = TC9_NOC_MODEL.total_power_mw()
        print(f"NoC Baseline (tc9): LUTs={noc_luts:,}, FFs={noc_ffs:,}, Power={noc_power:.1f}mW")
        return

    if args.features:
        features = [f.strip() for f in args.features.split(",")]
    else:
        # Default: show baseline NoC
        print("No features specified. Showing NoC baseline.")
        args.noc_only = True
        noc_luts = TC9_NOC_MODEL.total_luts()
        noc_ffs = TC9_NOC_MODEL.total_ffs()
        noc_power = TC9_NOC_MODEL.total_power_mw()
        print(f"NoC Baseline (tc9): LUTs={noc_luts:,}, FFs={noc_ffs:,}, Power={noc_power:.1f}mW")
        return

    print_estimates(features, include_breakdown=not args.no_breakdown)


if __name__ == "__main__":
    main()
