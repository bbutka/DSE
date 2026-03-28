from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from export_tc9_phase1_minizinc import write_tc9_phase1_dzn


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "minizinc" / "tc9_phase1.mzn"
DATA_PATH = BASE_DIR / "minizinc" / "tc9_phase1.dzn"


def main() -> None:
    written = write_tc9_phase1_dzn(DATA_PATH)
    print(f"Wrote MiniZinc data: {written}")

    minizinc = shutil.which("minizinc")
    if not minizinc:
        print("MiniZinc CLI is not installed on this machine.")
        print("Run this once MiniZinc is installed:")
        print(f'  minizinc "{MODEL_PATH}" "{DATA_PATH}"')
        return

    command = [minizinc, str(MODEL_PATH), str(DATA_PATH)]
    print("Running:", " ".join(f'"{part}"' if " " in part else part for part in command))
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
