% Linear interpolation rules for ln(x) over x in [1, 10^9]
%
% Requires:
%   - clingo_ln_lookup_table_1_to_1e9.lp
%   - input facts of the form: ln_query(Id, X).
%     where X is an integer in [1, 1000000000]
%
% Produces:
%   - ln_interp(Id, LnScaled).
%     where LnScaled ~= round(ln(X) * 1_000_000)
%
% Design:
%   1) Find the decade E so that X in [10^E, 10^(E+1)), with 10^9 handled explicitly.
%   2) Convert query to scaled x-space: XS = 1000 * X.
%   3) Interpolate between adjacent LUT entries in that decade.
%   4) Near the upper edge (mantissa > 9.990), interpolate between
%      ln_lut(E,9990,...) and ln_lut(E+1,1000,...).
%
% Notes:
%   - This is integer-only arithmetic.
%   - Interpolation is linear in x, not in ln(x).
%   - Output is usually much more accurate than nearest-bin lookup.
%
ln_scale(1000000).
mantissa_scale(1000).
mantissa_step(10).

exp_range(0,1,10).
exp_range(1,10,100).
exp_range(2,100,1000).
exp_range(3,1000,10000).
exp_range(4,10000,100000).
exp_range(5,100000,1000000).
exp_range(6,1000000,10000000).
exp_range(7,10000000,100000000).
exp_range(8,100000000,1000000000).

pow10(0,1).
pow10(1,10).
pow10(2,100).
pow10(3,1000).
pow10(4,10000).
pow10(5,100000).
pow10(6,1000000).
pow10(7,10000000).
pow10(8,100000000).
pow10(9,1000000000).

valid_ln_query(Id) :- ln_query(Id, X), X >= 1, X <= 1000000000.

% Determine decade exponent.
query_exp(Id, E) :-
    ln_query(Id, X),
    exp_range(E, Lo, Hi),
    X >= Lo, X < Hi.

query_exp(Id, 9) :-
    ln_query(Id, 1000000000).

% Query in x-scaled space, so LUT x values are integers:
% x_scaled = 1000 * x = mantissa_scaled * 10^E
query_xs(Id, XS) :-
    ln_query(Id, X),
    XS = 1000 * X.

% Rounded mantissa estimate: round(1000 * X / 10^E)
mantissa_raw(Id, MRaw) :-
    ln_query(Id, X),
    query_exp(Id, E),
    pow10(E, P),
    MRaw = (1000 * X + P / 2) / P.

% Standard lower bin for interpolation when inside the LUT body.
lower_bin(Id, MLo) :-
    mantissa_raw(Id, MRaw),
    MRaw <= 9990,
    MLo = (MRaw / 10) * 10.

upper_bin(Id, MHi) :-
    lower_bin(Id, MLo),
    MHi = MLo + 10.

% Exact hit on the top stored mantissa.
exact_top_bin(Id, 9990) :-
    mantissa_raw(Id, 9990).

% Upper-edge case: 9991..9999 uses bridge to next decade 1.000 * 10^(E+1)
upper_edge_case(Id) :-
    mantissa_raw(Id, MRaw),
    MRaw > 9990.

% Interpolation anchors inside a decade
interp_anchor(Id, E, XLo, XHi, LnLo, LnHi) :-
    query_exp(Id, E),
    lower_bin(Id, MLo),
    upper_bin(Id, MHi),
    pow10(E, P),
    ln_lut(E, MLo, LnLo),
    ln_lut(E, MHi, LnHi),
    XLo = MLo * P,
    XHi = MHi * P.

% Interpolation anchors at upper edge: [9.990 * 10^E, 1.000 * 10^(E+1)]
interp_anchor(Id, E, XLo, XHi, LnLo, LnHi) :-
    query_exp(Id, E),
    upper_edge_case(Id),
    E < 9,
    pow10(E, P),
    pow10(E+1, PNext),
    ln_lut(E, 9990, LnLo),
    ln_lut(E+1, 1000, LnHi),
    XLo = 9990 * P,
    XHi = 1000 * PNext.

% Exact hit on top stored mantissa avoids missing upper edge interpolation.
ln_interp(Id, LnScaled) :-
    query_exp(Id, E),
    exact_top_bin(Id, 9990),
    ln_lut(E, 9990, LnScaled).

% General interpolated result, rounded to nearest integer.
ln_interp(Id, LnScaled) :-
    valid_ln_query(Id),
    query_xs(Id, XS),
    interp_anchor(Id, _, XLo, XHi, LnLo, LnHi),
    DX = XHi - XLo,
    DX > 0,
    DeltaLn = LnHi - LnLo,
    LnScaled = LnLo + (DeltaLn * (XS - XLo) + DX / 2) / DX.

#show ln_interp/2.
