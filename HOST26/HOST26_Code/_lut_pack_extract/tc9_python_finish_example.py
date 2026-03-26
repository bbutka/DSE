# tc9_python_finish_example.py
#
# Optional Python-side exact/high-precision finishing step.
# Feed this script member probabilities exported from Clingo.

from fractions import Fraction
from decimal import Decimal, getcontext

getcontext().prec = 50

PROB_SCALE = 1_000_000

def exact_product_from_scaled(values, scale=PROB_SCALE):
    acc = Fraction(1, 1)
    for v in values:
        if v < 1:
            raise ValueError("Scaled probability must be >= 1")
        acc *= Fraction(v, scale)
    return acc

def decimal_product_from_scaled(values, scale=PROB_SCALE):
    acc = Decimal("1")
    s = Decimal(scale)
    for v in values:
        if v < 1:
            raise ValueError("Scaled probability must be >= 1")
        acc *= Decimal(v) / s
    return acc

if __name__ == "__main__":
    # Example values copied from the adapter example
    vals = [875000, 920000, 950000, 900000, 980000]

    exact = exact_product_from_scaled(vals)
    dec = decimal_product_from_scaled(vals)

    print("Exact product:", exact)
    print("Exact product float:", float(exact))
    print("Decimal product:", dec)
