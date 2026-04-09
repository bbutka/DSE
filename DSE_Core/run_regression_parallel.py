"""
Process-parallel regression runner for DSE_Core.

Two-tier scheduling:
  HEAVY targets (launch Clingo/CP-SAT solvers, ~1-2 GB each) are gated by a
  concurrency semaphore (default: 2 simultaneous heavy tests).  LIGHT targets
  (pure Python unit tests, <100 MB) run freely on remaining workers.

  This prevents memory overcommit while keeping CPU utilization high: light
  tests fill the gaps between heavy solver runs.

Memory safety net: even with tiered scheduling, the runner checks system
memory before launching any new process.  If usage exceeds the threshold
(default 80%), it pauses until memory drops.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

_DEFAULT_MEM_THRESHOLD_PCT = 80
_MEM_POLL_INTERVAL = 2.0
_MEM_WAIT_MAX = 120.0

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MODULES = [
    "tests.test_phase1_backends",
    "tests.test_runtime",
    "tests.test_regression",
    "tests.test_golden_baselines",
    "tests.test_phase3_fast",
    "tests.test_closed_loop_phase2",
]

# ---------------------------------------------------------------------------
# Target classification: HEAVY launches solvers (~1-2 GB), LIGHT is pure Python
# ---------------------------------------------------------------------------

_HEAVY_MARKERS = frozenset({
    # Golden baselines (full pipeline with Clingo Phase 2/3)
    "TestTC9GoldenBaselineFast",
    "TestTC9GoldenBaselineSlow",
    "TestDarpaUAVGoldenBaselineFast",
    "TestDarpaUAVGoldenBaselineSlow",
    "TestPixhawk6XGoldenBaselineFast",
    "TestPixhawk6XGoldenBaselineSlow",
    "TestOpenTitanPhase1GoldenBaselines",
    # Phase 1 backends (CP-SAT + ASP)
    "TestPhase1BackendIntegration",
    # Phase 1 integration (solver runs)
    "TestPhase1Integration",
    "TestRefSoCPhase1MinResources",
    "TestRefSoCPhase1Balanced",
    "TestRefSoCPhase1MaxSecurity",
    # Phase 2 integration (Clingo)
    "TestPhase2Integration",
    # Phase 3 integration (Clingo scenarios)
    "TestPhase3Integration",
    "TestPhase3FastParity",
    "TestPhase3FastPixhawkParity",
    "TestPhase3FastPixhawkDualPsParity",
    # Full pipeline (Phase 1+2+3)
    "TestFullPipeline",
    "TestRefSoCFullPipeline",
    # Runtime (Clingo solves)
    "TestRuntimeGoldenBaselines",
    "TestRuntimeJointIntegration",
    "TestRuntimeAdaptiveIntegration",
})

# Front-load priority: higher = runs earlier.  Heavy tests get highest
# priority so they start while light tests fill gaps.
_PRIORITY_MAP = {
    "TestTC9GoldenBaselineSlow": 110,
    "TestDarpaUAVGoldenBaselineSlow": 108,
    "TestPixhawk6XGoldenBaselineSlow": 106,
    "TestRefSoCPhase1MinResources": 100,
    "TestRefSoCPhase1Balanced": 95,
    "TestRefSoCPhase1MaxSecurity": 90,
    "TestRuntimeGoldenBaselines": 90,
    "TestRuntimeJointIntegration": 80,
    "TestPhase1BackendIntegration": 75,
    "TestFullPipeline": 70,
    "TestRefSoCFullPipeline": 65,
    "TestPhase1Integration": 60,
    "TestOpenTitanPhase1GoldenBaselines": 55,
    "TestTC9GoldenBaselineFast": 50,
    "TestDarpaUAVGoldenBaselineFast": 50,
    "TestPixhawk6XGoldenBaselineFast": 50,
    "TestPhase3FastPixhawkParity": 45,
    "TestPhase3FastPixhawkDualPsParity": 45,
    "TestPhase3Integration": 40,
    "TestPhase2Integration": 35,
    "TestRuntimeAdaptiveIntegration": 30,
}


def _is_heavy(target: str) -> bool:
    """Return True if the target launches solver processes."""
    for marker in _HEAVY_MARKERS:
        if marker in target:
            return True
    return False


def default_workers() -> int:
    cpu_count = max(1, os.cpu_count() or 1)
    return min(8, cpu_count)


def default_heavy_slots() -> int:
    """Max concurrent heavy (solver) tests.  Heuristic: 1 per 8 GB of RAM."""
    if _HAS_PSUTIL:
        total_gb = psutil.virtual_memory().total / (1024 ** 3)
        return max(1, min(4, int(total_gb / 8)))
    return 2


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
    heavy: bool = False


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
    priority = 0
    for marker, weight in _PRIORITY_MAP.items():
        if marker in target:
            priority = max(priority, weight)
    return (-priority, target)


def _wait_for_memory(threshold_pct: float, label: str = "") -> None:
    if not _HAS_PSUTIL:
        return
    mem = psutil.virtual_memory()
    if mem.percent < threshold_pct:
        return
    tag = f" [{label}]" if label else ""
    print(
        f"  [MEM] {mem.percent:.0f}% used ({mem.available // (1024**2)} MB free)"
        f" — throttling{tag}, waiting for <{threshold_pct:.0f}%...",
        flush=True,
    )
    waited = 0.0
    while waited < _MEM_WAIT_MAX:
        time.sleep(_MEM_POLL_INTERVAL)
        waited += _MEM_POLL_INTERVAL
        mem = psutil.virtual_memory()
        if mem.percent < threshold_pct:
            print(
                f"  [MEM] {mem.percent:.0f}% — resuming after {waited:.0f}s wait.",
                flush=True,
            )
            return
    print(
        f"  [MEM] Still {mem.percent:.0f}% after {waited:.0f}s — launching anyway.",
        flush=True,
    )


def run_target(
    target: str,
    python_exe: str,
    extra_env: dict[str, str],
    heavy_sem: threading.Semaphore,
    target_index: int = 0,
    total_targets: int = 0,
    mem_threshold: float = _DEFAULT_MEM_THRESHOLD_PCT,
) -> TargetResult:
    heavy = _is_heavy(target)
    short_name = target.rsplit(".", 1)[-1] if "." in target else target
    tag = " [HEAVY]" if heavy else ""

    if heavy:
        heavy_sem.acquire()
    try:
        _wait_for_memory(mem_threshold, short_name)
        print(f"  >> [{target_index}/{total_targets}] {short_name}{tag}", flush=True)
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
            heavy=heavy,
        )
    finally:
        if heavy:
            heavy_sem.release()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Two-tier parallel regression runner for DSE_Core.",
    )
    parser.add_argument(
        "modules", nargs="*", default=DEFAULT_MODULES,
        help="Unittest modules to shard.",
    )
    parser.add_argument(
        "--workers", type=int, default=default_workers(),
        help="Total parallel worker subprocesses (heavy + light combined).",
    )
    parser.add_argument(
        "--heavy-slots", type=int, default=0,
        help="Max concurrent heavy (solver) tests. Default: auto (1 per 8 GB RAM).",
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--scope", choices=("class", "case"), default="class")
    parser.add_argument("--list-targets", action="store_true")
    parser.add_argument("--slow-golden", action="store_true")
    parser.add_argument("--solver-threads", type=int, default=0)
    parser.add_argument(
        "--mem-threshold", type=float, default=_DEFAULT_MEM_THRESHOLD_PCT,
        help=f"Memory %% gate (default {_DEFAULT_MEM_THRESHOLD_PCT}).",
    )
    args = parser.parse_args()

    targets = discover_targets(args.modules, args.scope)
    if args.list_targets:
        for t in targets:
            tag = " [HEAVY]" if _is_heavy(t) else ""
            print(f"{t}{tag}")
        return 0

    heavy_count = sum(1 for t in targets if _is_heavy(t))
    light_count = len(targets) - heavy_count
    heavy_slots = args.heavy_slots if args.heavy_slots > 0 else default_heavy_slots()
    heavy_sem = threading.Semaphore(heavy_slots)

    extra_env: dict[str, str] = {}
    if args.slow_golden:
        extra_env["DSE_RUN_SLOW_GOLDEN"] = "1"
    solver_threads = args.solver_threads if args.solver_threads > 0 else default_threads_per_worker(args.workers)
    extra_env["DSE_CPSAT_THREADS"] = str(solver_threads)
    extra_env["DSE_CBC_THREADS"] = str(solver_threads)
    extra_env["DSE_CLINGO_THREADS"] = str(solver_threads)

    mem_threshold = args.mem_threshold
    if _HAS_PSUTIL:
        mem_info = psutil.virtual_memory()
        total_gb = mem_info.total / (1024 ** 3)
        print(
            f"Targets: {len(targets)} ({heavy_count} heavy, {light_count} light)\n"
            f"Workers: {args.workers} total, {heavy_slots} heavy slots, "
            f"{solver_threads} solver threads/worker\n"
            f"Memory:  {total_gb:.0f} GB total, {mem_info.available // (1024**2)} MB free, "
            f"gate at {mem_threshold:.0f}%",
            flush=True,
        )
    else:
        print(
            f"Targets: {len(targets)} ({heavy_count} heavy, {light_count} light)\n"
            f"Workers: {args.workers} total, {heavy_slots} heavy slots\n"
            f"(pip install psutil for memory-aware throttling)",
            flush=True,
        )

    failures: list[TargetResult] = []
    results: list[TargetResult] = []
    completed = 0
    start_all = time.perf_counter()
    total_targets = len(targets)
    submitted = 0

    # Submit ALL targets immediately — the heavy_sem inside run_target
    # ensures at most `heavy_slots` solver tests run concurrently.
    # Light tests run freely.  The ThreadPoolExecutor caps total
    # concurrent processes at `workers`.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map: dict[concurrent.futures.Future, str] = {}
        for target in targets:
            submitted += 1
            fut = pool.submit(
                run_target, target, args.python, extra_env, heavy_sem,
                target_index=submitted, total_targets=total_targets,
                mem_threshold=mem_threshold,
            )
            future_map[fut] = target

        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1
            status = "PASS" if result.returncode == 0 else "FAIL"
            tag = " [H]" if result.heavy else ""
            elapsed = time.perf_counter() - start_all
            print(
                f"[{completed}/{total_targets}] {status} "
                f"{result.target.rsplit('.', 1)[-1]}{tag} "
                f"({result.duration_s:.1f}s) [{elapsed:.0f}s elapsed]",
                flush=True,
            )
            if result.returncode != 0:
                failures.append(result)

    total_s = time.perf_counter() - start_all
    print(f"\nCompleted {len(results)} targets in {total_s:.1f}s", flush=True)
    print(f"Passed: {len(results) - len(failures)}  Failed: {len(failures)}", flush=True)

    if results:
        print("\nSlowest targets:", flush=True)
        for i, r in enumerate(
            sorted(results, key=lambda x: x.duration_s, reverse=True)[:10], 1,
        ):
            tag = " [H]" if r.heavy else ""
            status = "PASS" if r.returncode == 0 else "FAIL"
            print(f"  {i}. {r.target.rsplit('.', 1)[-1]}{tag} [{status}] {r.duration_s:.1f}s")

    if failures:
        print(f"\n{'='*60}", flush=True)
        print(f"{len(failures)} target(s) FAILED:", flush=True)
        print(f"{'='*60}", flush=True)
        for r in failures:
            print(f"\n--- {r.target} ({r.duration_s:.1f}s) ---")
            if r.stdout:
                print(r.stdout.rstrip())
            if r.stderr:
                print(r.stderr.rstrip())
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
