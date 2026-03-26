#script(python)
from clingo import Number
mu =0.5
omega=10

def compute_product_2(p1, p2):
    print(f"DEBUG compute_product_2: p1={p1}, p2={p2}")
    # Check for infinity or invalid values
    if str(p1) == '#inf' or str(p2) == '#inf':
        print(f"WARNING: Got infinity, returning 0")
        return Number(0)
    if not hasattr(p1, 'number') or not hasattr(p2, 'number'):
        print(f"ERROR: Invalid arguments")
        return Number(0)
    result = (p1.number / 1000.0) * (p2.number / 1000.0)
    final = int(round(result * 1000.0))
    print(f"DEBUG result: {result} -> {final}")
    return Number(final)

def compute_product_3(p1, p2, p3):
    print(f"DEBUG compute_product_3: p1={p1}, p2={p2}, p3={p3}")
    if any(str(p) == '#inf' for p in [p1, p2, p3]):
        print(f"WARNING: Got infinity, returning 0")
        return Number(0)
    if not all(hasattr(p, 'number') for p in [p1, p2, p3]):
        print(f"ERROR: Invalid arguments")
        return Number(0)
    result = (p1.number / 100.0) * (p2.number / 100.0) * (p3.number / 100.0)
    return Number(int(round(result * 100.0)))

def compute_product_4(p1, p2, p3, p4):
    print(f"DEBUG compute_product_4: p1={p1}, p2={p2}, p3={p3}, p4={p4}")
    if any(str(p) == '#inf' for p in [p1, p2, p3, p4]):
        print(f"WARNING: Got infinity, returning 0")
        return Number(0)
    if not all(hasattr(p, 'number') for p in [p1, p2, p3, p4]):
        print(f"ERROR: Invalid arguments")
        return Number(0)
    result = (p1.number / 100.0) * (p2.number / 100.0) * (p3.number / 100.0) * (p4.number / 100.0)
    return Number(int(round(result * 100.0)))

def compute_product_5(p1, p2, p3, p4, p5):
    print(f"DEBUG compute_product_5: p1={p1}, p2={p2}, p3={p3}, p4={p4}, p5={p5}")
    if any(str(p) == '#inf' for p in [p1, p2, p3, p4, p5]):
        print(f"WARNING: Got infinity, returning 0")
        return Number(0)
    if not all(hasattr(p, 'number') for p in [p1, p2, p3, p4, p5]):
        print(f"ERROR: Invalid arguments")
        return Number(0)
    result = (p1.number / 100.0) * (p2.number / 100.0) * (p3.number / 100.0) * (p4.number / 100.0) * (p5.number / 100.0)
    return Number(int(round(result * 100.0)))
#end.

% Calculate Probability (Vulnerability × Logging Factor)
probability_VxR(Asset, Action, Prob) :-
    asset(_, Asset, Action),
    selected_security(Asset, Security),
    selected_logging(Asset, LogFeature),
    vulnerability(Security, Vulnerability),
    logging(LogFeature, LogFactor),
    Prob = Vulnerability * LogFactor.
#show probability_VxR/3.

% Calculate Component Probability (max VxR per component) - prevent #inf
component_probability(Component, write, MaxProb) :-
    component(Component),
    MaxProb = #max { Prob : asset(Component, Asset, write), probability_VxR(Asset, write, Prob) },
    MaxProb != #inf.

component_probability(Component, read, MaxProb) :-
    component(Component),
    MaxProb = #max { Prob : asset(Component, Asset, read), probability_VxR(Asset, read, Prob) },
    MaxProb != #inf.

#show component_probability/3.

% ── Find first item in chain (for redundancy c1→c2→c3→c4→c5) ──
first(X) :- component(X), not redundant(Y,X) : component(Y).

% ── Build chain from first item ──
in_chain(X,X) :- first(X), redundant(X, _).
in_chain(X,Y) :- in_chain(X,Z), redundant(Z,Y).
#show in_chain/2.

% ── Representative ──
rep(X) :- first(X).

% ── Chain of 2 (READ) with guards ──
redundant_read_probability(R, @compute_product_2(P1, P2)) :-
    rep(R),
    redundant(C1, C2),
    #count { C : in_chain(R, C) } = 2,
    component_probability(C1, read, P1),
    component_probability(C2, read, P2),
    P1 > 0, P2 > 0, P1 != #inf, P2 != #inf.

% ── Chain of 3 (READ) ──
redundant_read_probability(R, @compute_product_3(P1, P2, P3)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3),
    #count { C : in_chain(R, C) } = 3,
    component_probability(C1, read, P1),
    component_probability(C2, read, P2),
    component_probability(C3, read, P3),
    P1 > 0, P2 > 0, P3 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf.

% ── Chain of 4 (READ) ──
redundant_read_probability(R, @compute_product_4(P1, P2, P3, P4)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3), redundant(C3, C4),
    #count { C : in_chain(R, C) } = 4,
    component_probability(C1, read, P1),
    component_probability(C2, read, P2),
    component_probability(C3, read, P3),
    component_probability(C4, read, P4),
    P1 > 0, P2 > 0, P3 > 0, P4 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf, P4 != #inf.

% ── Chain of 5 (READ) - matches testCase5_inst.lp redundant chain ──
redundant_read_probability(R, @compute_product_5(P1, P2, P3, P4, P5)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3), redundant(C3, C4), redundant(C4, C5),
    #count { C : in_chain(R, C) } = 5,
    component_probability(C1, read, P1),
    component_probability(C2, read, P2),
    component_probability(C3, read, P3),
    component_probability(C4, read, P4),
    component_probability(C5, read, P5),
    P1 > 0, P2 > 0, P3 > 0, P4 > 0, P5 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf, P4 != #inf, P5 != #inf.

% ── Chain of 2 (WRITE) ──
redundant_write_probability(R, @compute_product_2(P1, P2)) :-
    rep(R),
    redundant(C1, C2),
    #count { C : in_chain(R, C) } = 2,
    component_probability(C1, write, P1),
    component_probability(C2, write, P2),
    P1 > 0, P2 > 0, P1 != #inf, P2 != #inf.

% ── Chain of 3 (WRITE) ──
redundant_write_probability(R, @compute_product_3(P1, P2, P3)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3),
    #count { C : in_chain(R, C) } = 3,
    component_probability(C1, write, P1),
    component_probability(C2, write, P2),
    component_probability(C3, write, P3),
    P1 > 0, P2 > 0, P3 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf.

% ── Chain of 4 (WRITE) ──
redundant_write_probability(R, @compute_product_4(P1, P2, P3, P4)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3), redundant(C3, C4),
    #count { C : in_chain(R, C) } = 4,
    component_probability(C1, write, P1),
    component_probability(C2, write, P2),
    component_probability(C3, write, P3),
    component_probability(C4, write, P4),
    P1 > 0, P2 > 0, P3 > 0, P4 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf, P4 != #inf.

% ── Chain of 5 (WRITE) - matches testCase5_inst.lp: c1→c2→c3→c4→c5 ──
redundant_write_probability(R, @compute_product_5(P1, P2, P3, P4, P5)) :-
    rep(R),
    redundant(C1, C2), redundant(C2, C3), redundant(C3, C4), redundant(C4, C5),
    #count { C : in_chain(R, C) } = 5,
    component_probability(C1, write, P1),
    component_probability(C2, write, P2),
    component_probability(C3, write, P3),
    component_probability(C4, write, P4),
    component_probability(C5, write, P5),
    P1 > 0, P2 > 0, P3 > 0, P4 > 0, P5 > 0,
    P1 != #inf, P2 != #inf, P3 != #inf, P4 != #inf, P5 != #inf.

#show redundant_read_probability/2.
#show redundant_write_probability/2.

% ── Spread probability to chain members (c1-c5 from testCase5_inst.lp) ──
new_component_probability(X, read, P) :- in_chain(R,X), redundant_read_probability(R, P).
new_component_probability(X, write, P) :- in_chain(R,X), redundant_write_probability(R, P).

% ── Non-chain components (c6, c7, c8 from testCase5_inst.lp) ──
new_component_probability(C, Action, Prob) :-
    component_probability(C, Action, Prob),
    not in_chain(_, C),
    Prob > 0.

#show new_component_probability/3.