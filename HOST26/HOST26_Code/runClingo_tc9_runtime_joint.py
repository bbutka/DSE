from __future__ import annotations

from pathlib import Path

from tc9_runtime_joint import generate_joint_runtime_report, solve_joint_runtime_pipeline


def main() -> None:
    p1, joint, runtime_results = solve_joint_runtime_pipeline()
    report = generate_joint_runtime_report(p1, joint, runtime_results)
    print(report)

    out_path = Path(__file__).resolve().parent / "runtime_joint_summary_tc9.txt"
    out_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to: {out_path}")


if __name__ == "__main__":
    main()
