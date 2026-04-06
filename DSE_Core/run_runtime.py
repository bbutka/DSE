"""
run_runtime.py  -- testCase9 Runtime Adaptive & Joint Solver
============================================================
Thin CLI wrapper over the DSE agent pipeline for tc9 runtime workflows.

This script operates on the protected baseline produced by Phases 1 and 2.
It extends the standard DSE flow with runtime monitoring/adaptation; it is
not the same as Phase 3 resilience assessment in the RASACC paper.

Default mode:  Phase 1 -> Phase 2 -> adaptive runtime scenarios
Joint mode:    Phase 1 -> joint runtime (replaces Phase 2) -> adaptive scenarios

Usage:
    python run_runtime.py              # standard adaptive runtime
    python run_runtime.py --joint      # joint co-optimized Phase 2 + runtime
"""

from __future__ import annotations

import os
import sys
import argparse

# Force UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from dse_tool.agents.phase1_agent import Phase1Agent
from dse_tool.agents.phase2_agent import Phase2Agent
from dse_tool.agents.runtime_agent import (
    RuntimeAgent,
    RUNTIME_SCENARIOS,
)
from dse_tool.core.asp_generator import ASPGenerator, make_tc9_network

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CLINGO_DIR = os.path.join(BASE_DIR, "Clingo")
TC9_LP     = os.path.join(CLINGO_DIR, "tgt_system_tc9_inst.lp")


def run_standard(timeout: int = 60) -> None:
    """Phase 1 -> Phase 2 -> adaptive runtime scenarios."""
    print("=" * 78)
    print("  TC9 Runtime Adaptive Analysis (standard pipeline)")
    print("=" * 78)
    print()

    # Generate tc9 instance facts from NetworkModel
    model = make_tc9_network()
    instance_facts = ASPGenerator(model).generate()

    # Phase 1
    print("[Phase 1] Security DSE optimisation...")
    p1_agent = Phase1Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TC9_LP,
        strategy="max_security",
        extra_instance_facts=instance_facts,
        timeout=timeout,
    )
    p1 = p1_agent.run()
    if not p1.satisfiable:
        print("FATAL: Phase 1 unsatisfiable.")
        sys.exit(1)
    print(f"[Phase 1] Done -- total_risk={p1.total_risk()}, "
          f"luts={p1.total_luts}, power={p1.total_power}")

    # Phase 2
    print("[Phase 2] ZTA policy synthesis...")
    p2_agent = Phase2Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TC9_LP,
        phase1_result=p1,
        strategy="max_security",
        extra_instance_facts=instance_facts,
        timeout=timeout,
    )
    p2 = p2_agent.run()
    if not p2.satisfiable:
        print(f"FATAL: Phase 2 unsatisfiable -- {p2.unsat_reason}")
        sys.exit(1)
    print(f"[Phase 2] Done -- FWs={sorted(set(p2.placed_fws))}, "
          f"PS={sorted(set(p2.placed_ps))}")

    # Adaptive runtime
    print("[Runtime] Adaptive scenario evaluation...")
    rt_agent = RuntimeAgent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TC9_LP,
        extra_instance_facts=instance_facts,
        timeout=timeout,
    )
    results = rt_agent.solve_adaptive(p1, p2, scenarios=list(RUNTIME_SCENARIOS))

    # Report
    report = RuntimeAgent.generate_runtime_report(p1, p2, results)
    print()
    print(report)


def run_joint(timeout: int = 60) -> None:
    """Phase 1 -> joint runtime (replaces Phase 2) -> adaptive scenarios."""
    print("=" * 78)
    print("  TC9 Joint Policy + Runtime Synthesis")
    print("=" * 78)
    print()

    # Generate tc9 instance facts from NetworkModel
    model = make_tc9_network()
    instance_facts = ASPGenerator(model).generate()

    # Phase 1
    print("[Phase 1] Security DSE optimisation...")
    p1_agent = Phase1Agent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TC9_LP,
        strategy="max_security",
        extra_instance_facts=instance_facts,
        timeout=timeout,
    )
    p1 = p1_agent.run()
    if not p1.satisfiable:
        print("FATAL: Phase 1 unsatisfiable.")
        sys.exit(1)
    print(f"[Phase 1] Done -- total_risk={p1.total_risk()}, "
          f"luts={p1.total_luts}, power={p1.total_power}")

    # Joint runtime (replaces Phase 2)
    print("[Joint] Co-optimizing FW/PS + monitor placement...")
    rt_agent = RuntimeAgent(
        clingo_dir=CLINGO_DIR,
        testcase_lp=TC9_LP,
        extra_instance_facts=instance_facts,
        timeout=timeout,
    )
    joint = rt_agent.solve_joint(p1)
    if not joint.satisfiable:
        print("FATAL: Joint runtime solve unsatisfiable.")
        sys.exit(1)
    print(f"[Joint] Done -- FWs={joint.placed_fws}, PS={joint.placed_ps}, "
          f"monitors={joint.placed_monitors}, cost={joint.total_joint_runtime_cost}")

    # Adaptive runtime using joint output
    print("[Runtime] Adaptive scenario evaluation (using joint context)...")
    p2_compat = joint.to_phase2_result()
    extra_facts = joint.as_runtime_facts()
    results = rt_agent.solve_adaptive(
        p1, p2_compat,
        scenarios=list(RUNTIME_SCENARIOS),
        extra_runtime_facts=extra_facts,
    )

    # Report
    report = RuntimeAgent.generate_joint_runtime_report(p1, joint, results)
    print()
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TC9 runtime adaptive & joint solver"
    )
    parser.add_argument(
        "--joint", action="store_true",
        help="Use joint Phase 2 + runtime co-optimization instead of standard pipeline"
    )
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="Per-solve timeout in seconds (default: 60)"
    )
    args = parser.parse_args()

    if args.joint:
        run_joint(timeout=args.timeout)
    else:
        run_standard(timeout=args.timeout)


if __name__ == "__main__":
    main()

