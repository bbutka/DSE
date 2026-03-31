# Journal Strengthening Plan

## Target

Move the paper from a conference-style methods draft toward a journal-ready manuscript better suited to venues such as `Integration, the VLSI Journal`, `Microprocessors and Microsystems`, or a later `TCAD`-level submission after more validation.

## Reviewer Risks To Address

- the optimization model is not explicit enough to reproduce
- novelty is plausible but not sharply separated from prior SoC security and DSE work
- two-case evaluation is useful but still narrow for a journal claim
- exactness claims need careful calibration when one strategy point times out
- the manuscript still contains conference-draft and internal-note language

## Execution Strategy

### 1. Strengthen What Can Be Fixed In Writing Now

- make the risk model explicit
- document feature semantics and cost dimensions from the actual LP facts
- state exactly what each strategy optimizes
- explain what "exact" means operationally in the solver
- replace draft-meta language with journal-style prose
- sharpen related-work positioning around SoC security building blocks, communication security, and security-aware DSE

### 2. Preserve Claim Discipline

- keep the ASP framing as `exact or best-found`
- do not claim superiority over heuristics without a baseline
- describe the DARPA/UAV `min_resources` point as a timeout-limited best-found result

### 3. Identify Evidence Still Needed For A Stronger Journal Submission

- one comparative baseline: CP-SAT, MILP, or a defensible greedy heuristic
- one synthetic scaling sweep varying components, candidate features, and enforcement points
- one artifact/reproducibility appendix or repository package
- one additional SoC case or automatically generated family of instances

## Concrete Deliverables

### Delivered In This Pass

- `SOCC_2026_Paper_Draft_v4.md`
  - explicit cost/risk model
  - compact optimization-structure table
  - strengthened related-work positioning
  - journal-style discussion and limitations

### Still Recommended

- `Journal_Submission_Draft_v1.md`
  - after final target journal is selected
- `SCALING_RESULTS.md`
  - synthetic instance sweep
- `BASELINE_COMPARISON.md`
  - CP-SAT or MILP comparison if feasible

## Immediate Next Experimental Tasks

1. Generate 3-5 synthetic topologies by varying:
   - number of receiver components
   - number of buses
   - number of candidate firewall locations
   - redundancy-group size
2. Run all three strategies on each instance and record:
   - solve time
   - optimality status
   - total risk
   - LUTs / FFs / BRAM / power
3. Implement one lightweight baseline:
   - preferred: CP-SAT
   - fallback: greedy risk-first with post hoc policy placement
4. Add one concise artifact section:
   - LP files used
   - Python entry points
   - timeout settings
   - hardware budget source

## Acceptance Rule

The paper is journal-credible when it satisfies all of the following:

1. a reader can reconstruct the optimization problem from the manuscript alone
2. every major claim has a matching results table or explicit limitation
3. exactness language is calibrated to solver status
4. novelty is stated relative to at least three adjacent literature categories
5. evaluation includes either a baseline or a broader synthetic scaling study
