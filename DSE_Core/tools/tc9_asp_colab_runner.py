"""Run the long TC9 ASP Phase 1 job and export a portable artifact bundle.

This script is intended for Google Colab or other long-running remote
environments where the user wants to:
1. run the TC9 ASP Phase 1 solver to completion (or preserve best-so-far data),
2. compare the result against the MathOpt backend, and
3. download a compact artifact bundle back to the local workstation.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLINGO_DIR = PROJECT_ROOT / "Clingo"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from dse_tool.agents.phase1_agent import STRATEGY_EXTRA  # noqa: E402
from dse_tool.agents.phase1_mathopt_agent import Phase1MathOptAgent  # noqa: E402
from dse_tool.core.asp_generator import ASPGenerator, make_tc9_network  # noqa: E402
from dse_tool.core.solution_parser import Phase1Result, SolutionParser  # noqa: E402
from ip_catalog.xilinx_ip_catalog import export_security_features_to_lp  # noqa: E402
import clingo  # noqa: E402


PHASE1_LP_NAMES = [
    "security_features_inst.lp",
    "init_enc.lp",
    "opt_redundancy_generic_enc.lp",
    "opt_latency_enc.lp",
    "opt_power_enc.lp",
    "opt_resource_enc.lp",
    "bridge_enc.lp",
]

PARITY_LUT_TIEBREAK_EXTRA = (
    "% parity run: make weighted risk primary and LUTs a secondary tie-break\n"
    "total_weighted_risk_sum(R) :- R = #sum { WR, C, Asset, Action : weighted_risk(C, Asset, Action, WR) }.\n"
    "#show total_weighted_risk_sum/1.\n"
    "#minimize { R@2 : total_weighted_risk_sum(R) }.\n"
    "#minimize { L@1 : total_luts_used(L) }.\n"
)


def _phase1_summary(result: Phase1Result) -> dict[str, Any]:
    return {
        "satisfiable": result.satisfiable,
        "optimal": result.optimal,
        "total_risk": result.total_risk(),
        "total_luts": result.total_luts,
        "total_ffs": result.total_ffs,
        "total_power": result.total_power,
        "security": result.security,
        "realtime": result.realtime,
        "risk_per_asset_action": {
            f"{asset}:{action}": risk
            for (asset, action), risk in sorted(result.risk_per_asset_action().items())
        },
        "max_risk_per_asset": result.max_risk_per_asset(),
    }


def _build_lp_files() -> list[str]:
    return [str(CLINGO_DIR / name) for name in PHASE1_LP_NAMES]


def _build_clingo_flags(
    *,
    clingo_threads: int,
    clingo_parallel_mode: str,
    clingo_configuration: str | None,
) -> list[str]:
    flags = ["--warn=none", "--opt-mode=opt", "--opt-strategy=usc", "-n", "1"]
    if clingo_configuration:
        flags.append(f"--configuration={clingo_configuration}")
    else:
        flags.append("--configuration=jumpy")
    if clingo_threads > 1:
        flags.append(f"--parallel-mode={clingo_threads},{clingo_parallel_mode}")
    return flags


def _write_checkpoint(output_dir: Path, elapsed_s: int, model_index: int, atoms: list[str]) -> None:
    checkpoint = {
        "elapsed_s": elapsed_s,
        "model_index": model_index,
        "atom_count": len(atoms),
        "atoms": atoms,
    }
    label = f"t{elapsed_s:06d}_m{model_index:04d}"
    _write_json(output_dir / f"asp_checkpoint_{label}.json", checkpoint)
    (output_dir / f"asp_checkpoint_{label}.lp").write_text(
        "\n".join(atoms),
        encoding="utf-8",
    )
    _write_json(output_dir / "asp_checkpoint_latest.json", checkpoint)
    (output_dir / "asp_checkpoint_latest.lp").write_text("\n".join(atoms), encoding="utf-8")


def _append_log_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _get_rss_bytes() -> int | None:
    if sys.platform.startswith("win"):
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        )
        if ok:
            return int(counters.WorkingSetSize)
        return None

    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(rss)
        return int(rss) * 1024
    except Exception:
        return None


def _write_heartbeat(
    output_dir: Path,
    *,
    stage: str,
    elapsed_s: int,
    model_index: int,
    atom_count: int,
    last_cost: int,
    optimal_proven: bool,
) -> None:
    rss_bytes = _get_rss_bytes()
    payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stage": stage,
        "status": "running",
        "elapsed_s": elapsed_s,
        "model_index": model_index,
        "atom_count": atom_count,
        "last_cost": last_cost,
        "optimal_proven": optimal_proven,
        "rss_bytes": rss_bytes,
        "rss_mib": round(rss_bytes / (1024 * 1024), 2) if rss_bytes is not None else None,
    }
    _write_json(output_dir / "run_heartbeat_latest.json", payload)
    _append_log_line(
        output_dir / "run_heartbeat.log",
        json.dumps(payload, sort_keys=True),
    )
    _write_status(
        output_dir / "run_status.json",
        stage=stage,
        status="running",
        elapsed_s=elapsed_s,
        model_index=model_index,
        atom_count=atom_count,
        last_cost=last_cost,
        optimal_proven=optimal_proven,
        rss_bytes=rss_bytes,
        rss_mib=round(rss_bytes / (1024 * 1024), 2) if rss_bytes is not None else None,
    )
    print(
        f"[{stage}] elapsed={elapsed_s}s models={model_index} atoms={atom_count} "
        f"cost={last_cost} rss_mib={payload['rss_mib']}"
    )


def _run_asp_phase1(
    *,
    strategy: str,
    timeout: int,
    clingo_threads: int,
    clingo_parallel_mode: str,
    clingo_configuration: str | None,
    output_dir: Path,
    snapshot_interval: int,
    heartbeat_interval: int,
    lut_tiebreak: bool,
) -> tuple[dict[str, Any], Phase1Result | None]:
    _write_status(output_dir / "run_status.json", stage="asp_phase1:model_build", status="running")
    model = make_tc9_network()
    facts = ASPGenerator(model).generate()
    _write_status(output_dir / "run_status.json", stage="asp_phase1:export_features", status="running")
    export_security_features_to_lp(str(CLINGO_DIR / "security_features_inst.lp"))

    extra = facts
    strategy_extra = STRATEGY_EXTRA.get(strategy, "")
    if strategy_extra:
        extra = (extra + "\n" if extra else "") + strategy_extra
    if lut_tiebreak:
        extra = (extra + "\n" if extra else "") + PARITY_LUT_TIEBREAK_EXTRA

    ctl = clingo.Control(
        _build_clingo_flags(
            clingo_threads=clingo_threads,
            clingo_parallel_mode=clingo_parallel_mode,
            clingo_configuration=clingo_configuration,
        )
    )
    _write_status(output_dir / "run_status.json", stage="asp_phase1:load_lp_files", status="running")
    for path in _build_lp_files():
        ctl.load(path)
    if extra.strip():
        ctl.add("extra", [], extra)
    programs = [("base", [])]
    if extra.strip():
        programs.append(("extra", []))
    _write_status(output_dir / "run_status.json", stage="asp_phase1:grounding", status="running")
    ctl.ground(programs)
    _write_status(output_dir / "run_status.json", stage="asp_phase1:solving", status="running")

    state: dict[str, Any] = {
        "last_atoms": [],
        "last_cost": -1,
        "model_index": 0,
        "optimal_proven": False,
        "finished": False,
        "error": "",
        "result": None,
    }
    state_lock = threading.Lock()
    start = time.perf_counter()

    def on_model(model_obj: clingo.Model) -> None:
        atoms = [str(atom) for atom in model_obj.symbols(shown=True)]
        with state_lock:
            state["last_atoms"] = atoms
            state["model_index"] += 1
            state["last_cost"] = model_obj.cost[0] if model_obj.cost else -1
            state["optimal_proven"] = model_obj.optimality_proven

    solve_handle = ctl.solve(on_model=on_model, async_=True)
    last_snapshot_elapsed = -1
    last_snapshot_model = 0
    last_heartbeat_elapsed = -1
    timed_out = False
    while True:
        finished = solve_handle.wait(1)
        elapsed_s = int(time.perf_counter() - start)
        with state_lock:
            model_index = int(state["model_index"])
            atoms = list(state["last_atoms"])
            last_cost = int(state["last_cost"])
            optimal_proven = bool(state["optimal_proven"])
        if heartbeat_interval > 0 and (
            last_heartbeat_elapsed < 0 or elapsed_s - last_heartbeat_elapsed >= heartbeat_interval
        ):
            _write_heartbeat(
                output_dir,
                stage="asp_phase1",
                elapsed_s=elapsed_s,
                model_index=model_index,
                atom_count=len(atoms),
                last_cost=last_cost,
                optimal_proven=optimal_proven,
            )
            last_heartbeat_elapsed = elapsed_s
        if atoms and model_index != last_snapshot_model:
            if snapshot_interval <= 0 or elapsed_s != last_snapshot_elapsed:
                _write_checkpoint(output_dir, elapsed_s, model_index, atoms)
                last_snapshot_elapsed = elapsed_s
                last_snapshot_model = model_index
        if finished:
            break
        if timeout > 0 and elapsed_s >= timeout:
            timed_out = True
            solve_handle.cancel()
            break
    solve_result = solve_handle.get()

    with state_lock:
        atoms = list(state["last_atoms"])
        model_index = int(state["model_index"])
        last_cost = int(state["last_cost"])
        optimal_proven = bool(state["optimal_proven"])

    _write_heartbeat(
        output_dir,
        stage="asp_phase1",
        elapsed_s=int(time.perf_counter() - start),
        model_index=model_index,
        atom_count=len(atoms),
        last_cost=last_cost,
        optimal_proven=optimal_proven,
    )

    raw = {
        "status": "SAT",
        "cost": last_cost,
        "message": "",
        "atoms": atoms,
        "model_index": model_index,
        "optimal_proven": optimal_proven,
    }
    if timed_out:
        raw["status"] = "TIMEOUT"
        raw["message"] = f"Clingo timed out after {timeout}s"
    elif solve_result is None:
        raw["status"] = "ERROR"
        raw["message"] = "Solve returned None"
    elif solve_result.unsatisfiable:
        raw["status"] = "UNSAT"
        raw["message"] = "Problem is unsatisfiable"
        raw["atoms"] = []
    elif not atoms:
        raw["status"] = "ERROR"
        raw["message"] = "Solve completed without a model"

    parsed: Phase1Result | None = None
    if raw.get("atoms"):
        parsed_atoms = [
            clingo.parse_term(atom) if isinstance(atom, str) else atom
            for atom in raw["atoms"]
        ]
        parsed = SolutionParser.parse_phase1(parsed_atoms, strategy=strategy)
        parsed.satisfiable = True
        parsed.optimal = bool(raw.get("optimal_proven")) and raw.get("status") == "SAT"
    return raw, parsed


def _run_mathopt_phase1(*, strategy: str, timeout: int, cpsat_threads: int) -> tuple[Phase1Result, list[str]]:
    model = make_tc9_network()
    q: queue.Queue = queue.Queue()
    result = Phase1MathOptAgent(
        network_model=model,
        strategy=strategy,
        timeout=timeout,
        progress_queue=q,
        solver_config={
            "phase1_backend": "cpsat",
            "ilp_solver": "cpsat",
            "cpsat_threads": cpsat_threads,
        },
    ).run()
    logs: list[str] = []
    while not q.empty():
        _level, msg = q.get_nowait()
        logs.append(msg)
    return result, logs


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_status(path: Path, *, stage: str, status: str, **extra: Any) -> None:
    payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stage": stage,
        "status": status,
    }
    payload.update(extra)
    _write_json(path, payload)


def _write_markdown(
    path: Path,
    *,
    strategy: str,
    asp_raw: dict[str, Any],
    asp_result: Phase1Result | None,
    math_result: Phase1Result,
    compare: dict[str, Any],
    elapsed_s: float,
) -> None:
    lines = [
        "# TC9 ASP Colab Run",
        "",
        f"- Strategy: `{strategy}`",
        f"- Wall time: `{elapsed_s:.1f}s`",
        f"- ASP status: `{asp_raw.get('status')}`",
        f"- ASP message: `{asp_raw.get('message', '')}`",
        f"- ASP atoms captured: `{len(asp_raw.get('atoms', []))}`",
        f"- ASP parsed result available: `{bool(asp_result)}`",
        f"- MathOpt satisfiable: `{math_result.satisfiable}`",
        f"- Risk parity: `{compare['same_risk_per_asset_action']}`",
        f"- Max-asset parity: `{compare['same_max_risk_per_asset']}`",
        "",
    ]
    if asp_result:
        lines.extend(
            [
                "## ASP Summary",
                "",
                f"- Total risk: `{asp_result.total_risk()}`",
                f"- Total LUTs: `{asp_result.total_luts}`",
                "",
            ]
        )
    lines.extend(
        [
            "## MathOpt Summary",
            "",
            f"- Total risk: `{math_result.total_risk()}`",
            f"- Total LUTs: `{math_result.total_luts}`",
            "",
            "## Artifacts",
            "",
            "- `asp_phase1_raw.json`",
            "- `asp_phase1_atoms.txt`",
            "- `asp_phase1_summary.json`",
            "- `mathopt_phase1_summary.json`",
            "- `compare_asp_vs_mathopt.json`",
            "- `mathopt_progress.log`",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _bundle_directory(output_dir: Path, bundle_name: str) -> Path:
    bundle_path = output_dir / bundle_name
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(output_dir.iterdir()):
            if path == bundle_path:
                continue
            zf.write(path, arcname=path.name)
    return bundle_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "tools" / "colab_tc9_artifacts"))
    parser.add_argument("--strategy", default="max_security", choices=("max_security", "min_resources", "balanced"))
    parser.add_argument("--asp-timeout", type=int, default=0)
    parser.add_argument("--mathopt-timeout", type=int, default=120)
    parser.add_argument("--clingo-threads", type=int, default=max(1, min(2, os.cpu_count() or 2)))
    parser.add_argument("--clingo-parallel-mode", default="compete")
    parser.add_argument("--clingo-configuration", default=None)
    parser.add_argument("--cpsat-threads", type=int, default=1)
    parser.add_argument("--snapshot-interval", type=int, default=60)
    parser.add_argument("--heartbeat-interval", type=int, default=10)
    parser.add_argument("--lut-tiebreak", action="store_true")
    parser.add_argument("--bundle-name", default="tc9_asp_artifacts.zip")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_status(
        output_dir / "run_started.json",
        stage="startup",
        status="started",
        strategy=args.strategy,
        asp_timeout=args.asp_timeout,
        mathopt_timeout=args.mathopt_timeout,
        clingo_threads=args.clingo_threads,
        snapshot_interval=args.snapshot_interval,
        heartbeat_interval=args.heartbeat_interval,
        lut_tiebreak=args.lut_tiebreak,
    )
    _write_status(
        output_dir / "run_status.json",
        stage="startup",
        status="started",
        strategy=args.strategy,
    )

    started = time.perf_counter()
    _write_status(output_dir / "run_status.json", stage="asp_phase1", status="running")
    asp_raw, asp_result = _run_asp_phase1(
        strategy=args.strategy,
        timeout=args.asp_timeout,
        clingo_threads=args.clingo_threads,
        clingo_parallel_mode=args.clingo_parallel_mode,
        clingo_configuration=args.clingo_configuration,
        output_dir=output_dir,
        snapshot_interval=args.snapshot_interval,
        heartbeat_interval=args.heartbeat_interval,
        lut_tiebreak=args.lut_tiebreak,
    )
    _write_status(
        output_dir / "run_status.json",
        stage="asp_phase1",
        status="completed",
        asp_status=asp_raw.get("status"),
        asp_atoms=len(asp_raw.get("atoms", [])),
        asp_model_index=asp_raw.get("model_index", 0),
    )
    _write_status(output_dir / "run_status.json", stage="mathopt_phase1", status="running")
    math_result, math_logs = _run_mathopt_phase1(
        strategy=args.strategy,
        timeout=args.mathopt_timeout,
        cpsat_threads=args.cpsat_threads,
    )
    elapsed_s = time.perf_counter() - started

    compare = {
        "asp_status": asp_raw.get("status"),
        "asp_message": asp_raw.get("message", ""),
        "asp_has_atoms": bool(asp_raw.get("atoms")),
        "asp_parsed": bool(asp_result),
        "mathopt_satisfiable": math_result.satisfiable,
        "same_risk_per_asset_action": bool(
            asp_result and math_result.risk_per_asset_action() == asp_result.risk_per_asset_action()
        ),
        "same_max_risk_per_asset": bool(
            asp_result and math_result.max_risk_per_asset() == asp_result.max_risk_per_asset()
        ),
    }

    _write_json(
        output_dir / "asp_phase1_raw.json",
        {
            "status": asp_raw.get("status"),
            "cost": asp_raw.get("cost"),
            "message": asp_raw.get("message"),
            "model_index": asp_raw.get("model_index"),
            "optimal_proven": asp_raw.get("optimal_proven"),
            "atoms": [str(atom) for atom in asp_raw.get("atoms", [])],
        },
    )
    (output_dir / "asp_phase1_atoms.txt").write_text(
        "\n".join(str(atom) for atom in asp_raw.get("atoms", [])),
        encoding="utf-8",
    )
    if asp_result is not None:
        _write_json(output_dir / "asp_phase1_summary.json", _phase1_summary(asp_result))
    _write_json(output_dir / "mathopt_phase1_summary.json", _phase1_summary(math_result))
    _write_json(output_dir / "compare_asp_vs_mathopt.json", compare)
    (output_dir / "mathopt_progress.log").write_text("\n".join(math_logs), encoding="utf-8")
    _write_markdown(
        output_dir / "README.md",
        strategy=args.strategy,
        asp_raw=asp_raw,
        asp_result=asp_result,
        math_result=math_result,
        compare=compare,
        elapsed_s=elapsed_s,
    )

    bundle_path = _bundle_directory(output_dir, args.bundle_name)
    _write_status(
        output_dir / "run_status.json",
        stage="complete",
        status="completed",
        bundle_path=str(bundle_path),
        elapsed_s=round(elapsed_s, 3),
        asp_status=asp_raw.get("status"),
        mathopt_satisfiable=math_result.satisfiable,
    )
    print(json.dumps(
        {
            "output_dir": str(output_dir),
            "bundle_path": str(bundle_path),
            "elapsed_s": round(elapsed_s, 3),
            "asp_status": asp_raw.get("status"),
            "asp_atoms": len(asp_raw.get("atoms", [])),
            "asp_parsed": bool(asp_result),
            "mathopt_satisfiable": math_result.satisfiable,
            "same_risk_per_asset_action": compare["same_risk_per_asset_action"],
            "same_max_risk_per_asset": compare["same_max_risk_per_asset"],
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
