import argparse
import importlib.util
import json
import sys
import time
import zipfile
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_SCHEDULE = [60, 120, 300, 600, 1200, 1800, 3600]
DEFAULT_MAX_TIMEOUT = 21600
DEFAULT_MULTIPLIER = 2.0


class TeeLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, msg: str):
        print(msg, flush=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(msg)
            handle.write("\n")


def load_runner_module(source_root: str | Path | None = None):
    if source_root is None:
        import runClingo_darpa_uav as local_darpa
        return local_darpa

    source_root = Path(source_root).resolve()
    runner_path = source_root / "runClingo_darpa_uav.py"
    if not runner_path.exists():
        raise FileNotFoundError(f"Missing runner file: {runner_path}")

    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

    spec = importlib.util.spec_from_file_location("darpa_uav_source_runner", runner_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load runner module from {runner_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def patch_runner_log(darpa_module: Any, log_path: Path):
    original = darpa_module.log
    darpa_module.log = TeeLogger(log_path)
    try:
        yield
    finally:
        darpa_module.log = original


def _json_default(value: Any):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def phase1_optimise_with_timeout(darpa_module: Any,
                                 strategy: str = "min_resources",
                                 timeout_s: int | None = None,
                                 incumbent: dict[str, Any] | None = None) -> dict[str, Any]:
    t0 = time.time()
    darpa_module.log(f"[Phase 1] [{strategy}] Loading LP files...")
    from ip_catalog.xilinx_ip_catalog import export_security_features_to_lp

    export_security_features_to_lp(darpa_module.lp("security_features_inst.lp"))

    ctl = darpa_module.clingo.Control(["-n", "1", "--opt-mode=optN", "--warn=none"])
    for path in darpa_module.PHASE1_FILES:
        darpa_module.log(f"  Loading {Path(path).name}")
        ctl.load(path)

    extra = darpa_module.STRATEGY_EXTRA.get(strategy, "")
    if extra:
        ctl.add("strategy", [], extra)
    if incumbent is not None:
        bound_program = "\n".join(
            [
                f"incumbent_luts({incumbent['luts']}).",
                f"incumbent_wrisk({incumbent['weighted_risk_sum']}).",
                "weighted_risk_sum(S) :- S = #sum { WR,C,Asset,Action : weighted_risk(C,Asset,Action,WR) }.",
                ":- incumbent_luts(B), total_luts_used(L), L > B.",
                ":- incumbent_luts(B), total_luts_used(L), L == B, incumbent_wrisk(RB), weighted_risk_sum(S), S >= RB.",
                "#show weighted_risk_sum/1.",
            ]
        )
        ctl.add("bounds", [], bound_program)

    darpa_module.log(f"[Phase 1] [{strategy}] Grounding... ({time.time() - t0:.1f}s)")
    ctl.ground(
        [("base", [])]
        + ([("strategy", [])] if extra else [])
        + ([("bounds", [])] if incumbent is not None else [])
    )
    solve_desc = "until completion" if timeout_s is None else f"timeout={timeout_s}s"
    darpa_module.log(f"[Phase 1] [{strategy}] Grounding done ({time.time() - t0:.1f}s). Solving ({solve_desc})...")

    result = darpa_module.Phase1Result()
    last_model: list[Any] = []
    model_count = [0]

    def on_model(model):
        nonlocal last_model
        model_count[0] += 1
        last_model = list(model.symbols(shown=True))
        result.optimal = model.optimality_proven
        darpa_module.log(
            f"  [Phase 1] Model #{model_count[0]}  cost={model.cost}  "
            f"optimal_proven={model.optimality_proven}  ({time.time() - t0:.1f}s)"
        )

    with ctl.solve(on_model=on_model, async_=True) as handle:
        if timeout_s is None:
            finished = handle.wait()
        else:
            finished = handle.wait(timeout_s)
        if not finished:
            darpa_module.log(f"  [Phase 1] Timeout ({timeout_s}s) — interrupting, using best model found")
            handle.cancel()
        solve_result = handle.get()

    timed_out = (timeout_s is not None) and (not finished)
    result.optimal = solve_result.satisfiable and not timed_out and result.optimal

    if solve_result.unsatisfiable:
        if incumbent is not None:
            darpa_module.log("[Phase 1] No model better than incumbent — incumbent proven optimal.")
            return {
                "status": "INCUMBENT_PROVEN_OPTIMAL",
                "result": None,
                "timed_out": False,
                "wall_secs": round(time.time() - t0, 3),
                "incumbent": incumbent,
            }
        raise RuntimeError("Phase 1 UNSAT — check resource/risk budgets")
    if timed_out and not last_model:
        if incumbent is not None:
            darpa_module.log("[Phase 1] Timeout before any better model was found â€” keeping incumbent and extending timeout.")
            return {
                "status": "NO_BETTER_MODEL_BEFORE_TIMEOUT",
                "result": None,
                "timed_out": True,
                "wall_secs": round(time.time() - t0, 3),
                "incumbent": incumbent,
            }
        raise RuntimeError("Phase 1 timed out before finding any model")

    weighted_risk_sum = 0
    for sym in last_model:
        name, args = sym.name, sym.arguments
        if name == "selected_security" and len(args) == 2 and str(args[0]) in darpa_module.COMPONENTS:
            result.security[str(args[0])] = str(args[1])
        elif name == "selected_logging" and len(args) == 2 and str(args[0]) in darpa_module.COMPONENTS:
            result.logging[str(args[0])] = str(args[1])
        elif name == "new_risk" and len(args) == 4:
            result.new_risk.append((str(args[0]), str(args[1]), str(args[2]), args[3].number))
        elif name == "weighted_risk" and len(args) == 4:
            weighted_risk_sum += args[3].number
        elif name == "weighted_risk_sum" and len(args) == 1:
            weighted_risk_sum = args[0].number
        elif name == "total_luts_used" and len(args) == 1:
            result.total_luts = args[0].number
        elif name == "total_ffs_used" and len(args) == 1:
            result.total_ffs = args[0].number
        elif name == "total_dsps_used" and len(args) == 1:
            result.total_dsps = args[0].number
        elif name == "total_lutram_used" and len(args) == 1:
            result.total_lutram = args[0].number
        elif name == "total_bram_used" and len(args) == 1:
            result.total_bram = args[0].number
        elif name == "total_power_used" and len(args) == 1:
            result.total_power = args[0].number

    proven = "PROVEN" if result.optimal else "BEST-FOUND (timeout)"
    darpa_module.log(
        f"[Phase 1] [{strategy}] DONE in {time.time() - t0:.1f}s — "
        f"{proven}  Risk={result.total_risk()}  "
        f"LUTs={result.total_luts}/53200 ({100 * result.total_luts // 53200}%)"
    )
    for comp in sorted(result.security):
        darpa_module.log(
            f"  {comp:<14} sec={result.security[comp]:<16} "
            f"log={result.logging.get(comp, '?')}"
        )
    return {
        "status": "FOUND_MODEL",
        "result": result,
        "timed_out": timed_out,
        "wall_secs": round(time.time() - t0, 3),
        "weighted_risk_sum": weighted_risk_sum,
    }


def phase1_result_to_dict(result: Any) -> dict[str, Any]:
    return {
        "optimal": result.optimal,
        "risk": result.total_risk(),
        "max_risk_per_asset": result.max_risk_per_asset(),
        "security": dict(sorted(result.security.items())),
        "logging": dict(sorted(result.logging.items())),
        "new_risk": [
            {"component": comp, "asset": asset, "action": action, "risk": risk}
            for comp, asset, action, risk in result.new_risk
        ],
        "resources": {
            "luts": result.total_luts,
            "ffs": result.total_ffs,
            "dsps": result.total_dsps,
            "lutram": result.total_lutram,
            "bram": result.total_bram,
            "power_mw": result.total_power,
        },
    }


def phase2_result_to_dict(result: Any) -> dict[str, Any]:
    return {
        "satisfiable": result.satisfiable,
        "optimal": result.optimal,
        "total_cost": result.total_cost,
        "placed_fws": sorted(set(result.placed_fws)),
        "placed_ps": sorted(set(result.placed_ps)),
        "excess_privileges": sorted(set(result.excess_privileges)),
        "missing_privileges": sorted(set(result.missing_privileges)),
        "policy_tightness": result.policy_tightness,
        "over_privileged": sorted(set(result.over_privileged)),
        "trust_gap_rot": sorted(set(result.trust_gap_rot)),
        "trust_gap_sboot": sorted(set(result.trust_gap_sboot)),
        "trust_gap_attest": sorted(set(result.trust_gap_attest)),
        "trust_gap_keys": sorted(set(result.trust_gap_keys)),
        "unattested_access": sorted(set(result.unattested_access)),
        "unsigned_ps": sorted(set(result.unsigned_ps)),
        "critical_exceptions": [list(item) for item in result.critical_exceptions],
        "unexplained_exceptions": [list(item) for item in result.unexplained_exceptions],
    }


def scenario_result_to_dict(result: Any) -> dict[str, Any]:
    return {
        "name": result.name,
        "compromised": result.compromised,
        "failed": result.failed,
        "satisfiable": result.satisfiable,
        "total_risk": result.total_risk,
        "total_risk_scaled": result.total_risk_scaled,
        "blast_radii": result.blast_radii,
        "effective_blast_radii": result.eff_blast_radii,
        "services_ok": result.services_ok,
        "services_degraded": result.services_degraded,
        "services_unavailable": result.services_unavail,
        "capabilities_lost": result.cap_lost,
        "capabilities_degraded": result.cap_degraded,
        "capabilities_available": result.cap_available,
        "cp_degraded": result.cp_degraded,
        "cp_stale": result.cp_stale,
        "cp_compromised": result.cp_compromised,
        "attack_paths": [list(item) for item in result.attack_paths],
        "escalation_paths": [list(item) for item in result.escalation_paths],
    }


def _worst_scenario(scenarios: list[Any]) -> tuple[Any | None, Any | None]:
    sat_scenarios = [scenario for scenario in scenarios if scenario.satisfiable]
    worst = max(sat_scenarios, key=lambda scenario: scenario.total_risk) if sat_scenarios else None
    baseline = next((scenario for scenario in sat_scenarios if scenario.name == "baseline"), None)
    return worst, baseline


def build_summary(attempts: list[dict[str, Any]], p1: Any, p2: Any | None, scenarios: list[Any]) -> dict[str, Any]:
    worst, baseline = _worst_scenario(scenarios)
    return {
        "case": "DARPA_UAV",
        "strategy": "min_resources",
        "optimality_proven": p1.optimal,
        "attempt_count": len(attempts),
        "final_timeout_s": attempts[-1]["timeout_s"],
        "total_phase1_wall_secs": round(sum(a["wall_secs"] for a in attempts), 3),
        "phase1": phase1_result_to_dict(p1),
        "phase2": phase2_result_to_dict(p2) if p2 is not None else None,
        "phase3": {
            "scenario_count": len(scenarios),
            "baseline_risk": baseline.total_risk if baseline is not None else None,
            "worst_scenario": worst.name if worst is not None else None,
            "worst_risk": worst.total_risk if worst is not None else None,
            "worst_ratio": (
                round(worst.total_risk / baseline.total_risk, 3)
                if worst is not None and baseline is not None and baseline.total_risk
                else None
            ),
        },
    }


def summary_markdown(summary: dict[str, Any]) -> str:
    phase1 = summary["phase1"]
    resources = phase1["resources"]
    phase2 = summary.get("phase2") or {}
    phase3 = summary.get("phase3") or {}
    lines = [
        "# DARPA UAV Min-Resources Optimality Run",
        "",
        f"- Optimality proven: `{summary['optimality_proven']}`",
        f"- Attempt count: `{summary['attempt_count']}`",
        f"- Final timeout (s): `{summary['final_timeout_s']}`",
        f"- Total Phase 1 wall time (s): `{summary['total_phase1_wall_secs']}`",
        "",
        "## Phase 1",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Risk | {phase1['risk']} |",
        f"| LUTs | {resources['luts']} |",
        f"| FFs | {resources['ffs']} |",
        f"| DSPs | {resources['dsps']} |",
        f"| LUTRAM | {resources['lutram']} |",
        f"| BRAM | {resources['bram']} |",
        f"| Power (mW) | {resources['power_mw']} |",
        "",
        "## Phase 2",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| SAT | {phase2.get('satisfiable')} |",
        f"| Optimal | {phase2.get('optimal')} |",
        f"| Firewalls | {len(phase2.get('placed_fws', []))} |",
        f"| Policy servers | {len(phase2.get('placed_ps', []))} |",
        f"| Excess privileges | {len(phase2.get('excess_privileges', []))} |",
        f"| No-RoT trust gaps | {len(phase2.get('trust_gap_rot', []))} |",
        "",
        "## Phase 3",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Scenario count | {phase3.get('scenario_count')} |",
        f"| Baseline risk | {phase3.get('baseline_risk')} |",
        f"| Worst scenario | {phase3.get('worst_scenario')} |",
        f"| Worst risk | {phase3.get('worst_risk')} |",
        f"| Worst ratio | {phase3.get('worst_ratio')} |",
        "",
    ]
    return "\n".join(lines)


def bundle_outputs(output_dir: Path) -> Path:
    zip_path = output_dir / "darpa_uav_min_resources_optimality_bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(output_dir.iterdir()):
            if path.name == zip_path.name:
                continue
            bundle.write(path, arcname=path.name)
    return zip_path


def _write_json(path: Path, payload: Any):
    path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


def run_until_optimal(output_dir: str | Path,
                      source_root: str | Path | None = None,
                      timeout_schedule: list[int] | None = None,
                      max_timeout: int = DEFAULT_MAX_TIMEOUT,
                      timeout_multiplier: float = DEFAULT_MULTIPLIER,
                      run_phase2: bool = True,
                      run_phase3: bool = True) -> dict[str, Any]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "darpa_uav_min_resources_optimality.log"
    attempts_path = output_dir / "attempts.json"
    attempts: list[dict[str, Any]] = []
    timeouts = list(timeout_schedule or DEFAULT_TIMEOUT_SCHEDULE)
    overall_start = time.perf_counter()
    darpa = load_runner_module(source_root)

    with patch_runner_log(darpa, log_path):
        darpa.log(f"[RUNNER] Output directory: {output_dir}")
        darpa.log(f"[RUNNER] Source root: {source_root or 'local workspace'}")
        darpa.log(f"[RUNNER] Timeout schedule: {timeouts}")
        darpa.log(f"[RUNNER] Max timeout: {max_timeout}")

        attempt_index = 0
        final_p1 = None
        incumbent: dict[str, Any] | None = None

        while True:
            if attempt_index < len(timeouts):
                timeout_s = timeouts[attempt_index]
            else:
                timeout_s = int(round(timeouts[-1] * timeout_multiplier))
                timeout_s = max(timeout_s, timeouts[-1] + 1)
                timeouts.append(timeout_s)

            if timeout_s > max_timeout:
                raise RuntimeError(
                    f"Reached timeout {timeout_s}s beyond max_timeout={max_timeout}s without proving optimality."
                )

            darpa.log(f"[RUNNER] Attempt {attempt_index + 1} with timeout {timeout_s}s")
            phase1_run = phase1_optimise_with_timeout(
                darpa,
                strategy="min_resources",
                timeout_s=timeout_s,
                incumbent=incumbent,
            )

            if phase1_run["status"] == "INCUMBENT_PROVEN_OPTIMAL":
                if incumbent is None:
                    raise RuntimeError("Incumbent proof returned without an incumbent result.")
                attempts.append(
                    {
                        "attempt": attempt_index + 1,
                        "timeout_s": timeout_s,
                        "wall_secs": phase1_run["wall_secs"],
                        "status": phase1_run["status"],
                        "optimality_proven": True,
                        "risk": incumbent["risk"],
                        "weighted_risk_sum": incumbent["weighted_risk_sum"],
                        "luts": incumbent["luts"],
                        "ffs": incumbent["ffs"],
                        "lutram": incumbent["lutram"],
                        "bram": incumbent["bram"],
                        "power_mw": incumbent["power_mw"],
                    }
                )
                final_p1 = incumbent["result"]
                darpa.log(f"[RUNNER] Incumbent proven optimal on attempt {attempt_index + 1}")
                _write_json(attempts_path, attempts)
                break

            if phase1_run["status"] == "NO_BETTER_MODEL_BEFORE_TIMEOUT":
                if incumbent is None:
                    raise RuntimeError("Timeout status returned without an incumbent result.")
                attempts.append(
                    {
                        "attempt": attempt_index + 1,
                        "timeout_s": timeout_s,
                        "wall_secs": phase1_run["wall_secs"],
                        "status": phase1_run["status"],
                        "optimality_proven": False,
                        "risk": incumbent["risk"],
                        "weighted_risk_sum": incumbent["weighted_risk_sum"],
                        "luts": incumbent["luts"],
                        "ffs": incumbent["ffs"],
                        "lutram": incumbent["lutram"],
                        "bram": incumbent["bram"],
                        "power_mw": incumbent["power_mw"],
                    }
                )
                _write_json(attempts_path, attempts)
                attempt_index += 1
                continue

            p1 = phase1_run["result"]
            incumbent = {
                "result": p1,
                "risk": p1.total_risk(),
                "weighted_risk_sum": phase1_run["weighted_risk_sum"],
                "luts": p1.total_luts,
                "ffs": p1.total_ffs,
                "lutram": p1.total_lutram,
                "bram": p1.total_bram,
                "power_mw": p1.total_power,
            }

            attempts.append(
                {
                    "attempt": attempt_index + 1,
                    "timeout_s": timeout_s,
                    "wall_secs": phase1_run["wall_secs"],
                    "status": phase1_run["status"],
                    "optimality_proven": p1.optimal,
                    "risk": incumbent["risk"],
                    "weighted_risk_sum": incumbent["weighted_risk_sum"],
                    "luts": incumbent["luts"],
                    "ffs": incumbent["ffs"],
                    "lutram": incumbent["lutram"],
                    "bram": incumbent["bram"],
                    "power_mw": incumbent["power_mw"],
                    "security": dict(sorted(p1.security.items())),
                    "logging": dict(sorted(p1.logging.items())),
                }
            )
            _write_json(attempts_path, attempts)

            if p1.optimal:
                final_p1 = p1
                darpa.log(f"[RUNNER] Optimality proven on attempt {attempt_index + 1}")
                break

            attempt_index += 1

        phase2_start = time.perf_counter()
        p2 = darpa.phase2_zta(final_p1) if run_phase2 else None
        phase2_secs = round(time.perf_counter() - phase2_start, 3) if run_phase2 else 0.0

        phase3_start = time.perf_counter()
        scenarios = darpa.phase3_all(final_p1, p2) if run_phase3 and p2 is not None else []
        phase3_secs = round(time.perf_counter() - phase3_start, 3) if run_phase3 and p2 is not None else 0.0

    summary = build_summary(attempts, final_p1, p2, scenarios)
    summary["phase2_wall_secs"] = phase2_secs
    summary["phase3_wall_secs"] = phase3_secs
    summary["total_wall_secs"] = round(time.perf_counter() - overall_start, 3)
    summary["completed_utc"] = datetime.now(timezone.utc).isoformat()

    report_text = darpa.generate_report(final_p1, p2, scenarios) if p2 is not None else ""

    _write_json(output_dir / "summary.json", summary)
    _write_json(output_dir / "phase1_result.json", phase1_result_to_dict(final_p1))
    if p2 is not None:
        _write_json(output_dir / "phase2_result.json", phase2_result_to_dict(p2))
    if scenarios:
        _write_json(output_dir / "phase3_scenarios.json", [scenario_result_to_dict(s) for s in scenarios])

    (output_dir / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")
    (output_dir / "darpa_uav_min_resources_report.txt").write_text(report_text, encoding="utf-8")
    (output_dir / "darpa_uav_min_resources_p1_facts.lp").write_text(final_p1.as_p1_facts(), encoding="utf-8")

    manifest = {
        "output_dir": str(output_dir),
        "files": sorted(path.name for path in output_dir.iterdir() if path.is_file()),
    }
    _write_json(output_dir / "artifact_manifest.json", manifest)
    bundle_path = bundle_outputs(output_dir)
    manifest["bundle_zip"] = bundle_path.name
    _write_json(output_dir / "artifact_manifest.json", manifest)

    return {
        "summary": summary,
        "bundle_zip": str(bundle_path),
        "output_dir": str(output_dir),
        "manifest": manifest,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run DARPA UAV min_resources until optimality is proven and save artifacts."
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--source-root")
    parser.add_argument("--timeouts", nargs="*", type=int, default=DEFAULT_TIMEOUT_SCHEDULE)
    parser.add_argument("--max-timeout", type=int, default=DEFAULT_MAX_TIMEOUT)
    parser.add_argument("--timeout-multiplier", type=float, default=DEFAULT_MULTIPLIER)
    parser.add_argument("--skip-phase2", action="store_true")
    parser.add_argument("--skip-phase3", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    result = run_until_optimal(
        output_dir=args.output_dir,
        source_root=args.source_root,
        timeout_schedule=args.timeouts,
        max_timeout=args.max_timeout,
        timeout_multiplier=args.timeout_multiplier,
        run_phase2=not args.skip_phase2,
        run_phase3=not args.skip_phase3,
    )
    print(json.dumps(result["summary"], indent=2), flush=True)
    print(result["bundle_zip"], flush=True)


if __name__ == "__main__":
    main()
