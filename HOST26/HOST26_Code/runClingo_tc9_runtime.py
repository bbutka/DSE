from __future__ import annotations

from pathlib import Path

from tc9_runtime_adaptive import generate_runtime_report, solve_all_runtime_scenarios


def main() -> None:
    p1, p2, results = solve_all_runtime_scenarios()
    report = generate_runtime_report(p1, p2, results)
    print(report)

    out_path = Path(__file__).resolve().parent / "runtime_adaptive_summary_tc9.txt"
    out_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to: {out_path}")


if __name__ == "__main__":
    main()
