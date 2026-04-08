"""
Process-parallel regression runner for DSE_Core.

Runs unittest targets at class granularity in separate Python processes so
solver-heavy classes can use more of the machine than the default serial
`python -m unittest ...` flow.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MODULES = [
    "tests.test_phase1_backends",
    "tests.test_runtime",
    "tests.test_regression",
    "tests.test_golden_baselines",
]


def default_workers() -> int:
    cpu_count = max(1, os.cpu_count() or 1)
    return min(8, cpu_count)


def default_threads_per_worker(workers: int) -> int:
    cpu_count = max(1, os.cpu_count() or 1)
    share = max(1, cpu_count // max(1, workers))
    if share >= 8:
        return 4
    if share >= 4:
        return 2
    return 1


@dataclass
class TargetResult:
    target: str
    returncode: int
    duration_s: float
    stdout: str
    stderr: str


def _iter_cases(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _iter_cases(test)
        else:
            yield test


def discover_targets(module_names: list[str], scope: str) -> list[str]:
    loader = unittest.defaultTestLoader
    targets: list[str] = []
    seen: set[str] = set()
    for module_name in module_names:
        suite = loader.loadTestsFromName(module_name)
        for case in _iter_cases(suite):
            test_id = case.id()
            if test_id.startswith("unittest.loader._FailedTest"):
                if module_name not in seen:
                    seen.add(module_name)
                    targets.append(module_name)
                continue
            target = test_id if scope == "case" else test_id.rsplit(".", 1)[0]
            if target not in seen:
                seen.add(target)
                targets.append(target)
    targets.sort(key=_target_sort_key)
    return targets


def _target_sort_key(target: str) -> tuple[int, str]:
    """
    Front-load likely long-running solver tests to reduce end-of-suite tail collapse.
    """
    priority = 0
    heavy_markers = {
        "TestTC9GoldenBaselineSlow": 110,
        "TestDarpaUAVGoldenBaselineSlow": 108,
        "TestPixhawk6XGoldenBaselineSlow": 106,
        "test_refsoc_phase1_all_strategies": 100,
        "TestRefSoCPhase1MinResources": 100,
        "test_refsoc_phase1_min_resources": 100,
        "TestRefSoCPhase1Balanced": 95,
        "test_refsoc_phase1_balanced": 95,
        "TestRefSoCPhase1MaxSecurity": 90,
        "test_refsoc_phase1_max_security": 90,
        "TestRuntimeGoldenBaselines": 90,
        "TestRuntimeJointIntegration": 80,
        "TestPhase1BackendIntegration": 75,
        "TestFullPipeline": 70,
        "TestPhase1Integration": 60,
        "TestOpenTitanPhase1GoldenBaselines": 55,
        "TestTC9GoldenBaselineFast": 50,
        "TestDarpaUAVGoldenBaselineFast": 50,
    }
    for marker, weight in heavy_markers.items():
        if marker in target:
            priority = max(priority, weight)
    return (-priority, target)


def run_target(target: str, python_exe: str, extra_env: dict[str, str]) -> TargetResult:
    cmd = [python_exe, "-m", "unittest", target, "-v"]
    env = os.environ.copy()
    env.update(extra_env)
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    duration_s = time.perf_counter() - started
    return TargetResult(
        target=target,
        returncode=proc.returncode,
        duration_s=duration_s,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DSE_Core unittest targets in parallel.")
    parser.add_argument(
        "modules",
        nargs="*",
        default=DEFAULT_MODULES,
        help="Unittest modules to shard. Defaults to the main DSE_Core regression modules.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers(),
        help="Number of parallel worker subprocesses.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter to use for each unittest subprocess.",
    )
    parser.add_argument(
        "--scope",
        choices=("class", "case"),
        default="class",
        help="Shard by unittest class or individual test case.",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="Print discovered class targets and exit.",
    )
    parser.add_argument(
        "--slow-golden",
        action="store_true",
        help="Enable slow golden baseline suites.",
    )
    parser.add_argument(
        "--solver-threads",
        type=int,
        default=0,
        help="Per-process Phase 1/Clingo solver threads. Defaults to a heuristic based on --workers.",
    )
    args = parser.parse_args()

    targets = discover_targets(args.modules, args.scope)
    if args.list_targets:
        for target in targets:
            print(target)
        return 0

    extra_env: dict[str, str] = {}
    if args.slow_golden:
        extra_env["DSE_RUN_SLOW_GOLDEN"] = "1"
    solver_threads = args.solver_threads if args.solver_threads > 0 else default_threads_per_worker(args.workers)
    extra_env["DSE_CPSAT_THREADS"] = str(solver_threads)
    extra_env["DSE_CBC_THREADS"] = str(solver_threads)
    extra_env["DSE_CLINGO_THREADS"] = str(solver_threads)

    print(
        f"Discovered {len(targets)} {args.scope} targets; running with "
        f"{args.workers} workers and {solver_threads} solver threads per worker."
    )
    failures: list[TargetResult] = []
    results: list[TargetResult] = []
    completed = 0
    start_all = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {
            pool.submit(run_target, target, args.python, extra_env): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1
            status = "PASS" if result.returncode == 0 else "FAIL"
            print(f"[{completed}/{len(targets)}] {status} {result.target} ({result.duration_s:.1f}s)")
            if result.returncode != 0:
                failures.append(result)

    total_s = time.perf_counter() - start_all
    print(f"Completed in {total_s:.1f}s")
    print(f"Passed: {len(results) - len(failures)}  Failed: {len(failures)}")

    if results:
        print()
        print("Slowest targets:")
        for index, result in enumerate(
            sorted(results, key=lambda item: item.duration_s, reverse=True)[: min(10, len(results))],
            start=1,
        ):
            status = "PASS" if result.returncode == 0 else "FAIL"
            print(f"  {index}. {result.target} [{status}] {result.duration_s:.1f}s")

    if failures:
        print()
        print(f"{len(failures)} target(s) failed:")
        print()
        for result in failures:
            print(f"=== {result.target} ({result.duration_s:.1f}s) ===")
            if result.stdout:
                print(result.stdout.rstrip())
            if result.stderr:
                print(result.stderr.rstrip())
            print()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
