from __future__ import annotations

from itertools import product
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "Clingo" / "tc9_combined_prob_norm_size5_lut.lp"

NORMALIZED_VALUES = (25, 76, 128, 179, 282, 384, 589)
DIVISOR = 100_000_000


def main() -> None:
    lines = [
        "% tc9_combined_prob_norm_size5_lut.lp",
        "%",
        "% Exact LUT replacement for the size-5 combined_prob_norm rule in",
        "% opt_redundancy_enc.lp. The inputs are the same integer-normalized",
        "% probabilities produced by original_prob_normalized/2.",
        "%",
        "% combined_prob_norm_size5_lut(P1,P2,P3,P4,P5,P) :-",
        "%     P = (P1 * P2 * P3 * P4 * P5) / 100000000.",
        "",
    ]

    for values in product(NORMALIZED_VALUES, repeat=5):
        result = (values[0] * values[1] * values[2] * values[3] * values[4]) // DIVISOR
        args = ",".join(str(value) for value in values)
        lines.append(f"combined_prob_norm_size5_lut({args},{result}).")

    OUTPUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
