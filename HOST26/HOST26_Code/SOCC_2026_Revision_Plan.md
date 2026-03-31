# SOCC 2026 Revision Plan

## Goal

Address the current paper weaknesses that would likely trigger reviewer pushback:

- unsupported exact-vs-heuristic claims
- incomplete strategy-front evidence on the primary case
- missing runtime/scaling evidence
- insufficiently explicit risk/objective formulation
- thin novelty positioning
- draft-state manuscript artifacts

## Decision Rule

The paper is submission-ready only if all of the following are true:

1. TC9 has verified `max_security`, `min_resources`, and `balanced` results.
2. A runtime/scaling table exists for TC9 and UAV.
3. The risk/objective model is explicitly documented in one compact table or subsection.
4. The paper either includes a real heuristic baseline or removes strong comparative claims against heuristics.
5. Figure-note and draft-note language is removed from the manuscript.

If any of these are missing by the final week before submission, weaken claims rather than leaving evidence gaps.

## Workstreams

### Workstream 1: Evidence Completion

#### Task 1.1 - TC9 three-strategy analysis

Generate and record, for `max_security`, `min_resources`, and `balanced`:

- total risk
- total LUTs
- total FFs
- BRAM / LUTRAM / DSPs if available
- power
- firewalls placed
- policy servers placed
- excess privileges
- trust gaps
- optimality status
- worst scenario and amplification

Deliverable:

- `SOCC_2026_TC9_Strategy_Evidence.md`

Use:

- `dse_tool.core.asp_generator.make_tc9_network`
- `Phase1Agent`
- `Phase2Agent`
- `Phase3Agent`

#### Task 1.2 - Runtime/scaling table

Measure, at minimum:

- Phase 1 runtime
- Phase 2 runtime
- Phase 3 runtime
- total runtime
- number of scenarios
- optimality status

For:

- TC9
- translated UAV

Deliverable:

- `SOCC_2026_Runtime_Table.md`

#### Task 1.3 - Heuristic comparison decision

Choose one path:

- Path A: run a lightweight baseline comparison using existing CP-SAT / comparison material
- Path B: remove strong “better than heuristics” language and retain only “exact alternative” language

Stop/go:

- If a credible baseline cannot be generated quickly, use Path B.

Deliverable:

- manuscript edits plus one sentence in the revision log explaining the decision

### Workstream 2: Reproducibility and Method Clarity

#### Task 2.1 - Risk/objective compact specification

Create one compact method table covering:

- security feature choices
- logging feature choices
- cost dimensions
- hard constraints
- optimization objective(s)
- strategy-specific objective modifiers

Deliverable:

- `SOCC_2026_Method_Table_Seed.md`

#### Task 2.2 - Manuscript method tightening

Revise the paper so the following are explicit:

- what is minimized
- what is constrained
- what “exact” means operationally
- what changes across strategies

Stop/go:

- if a reader cannot reconstruct the optimization problem from the paper, the section is still too abstract

### Workstream 3: Novelty Positioning

#### Task 3.1 - Related-work expansion

Add 3-5 more directly relevant references in:

- SoC/interconnect security
- hardware firewall / NoC protection
- hardware-security DSE
- exact constraint-based architecture synthesis

Deliverable:

- updated related-work section in manuscript v3

#### Task 3.2 - Claim calibration

For every major claim, ensure one matching evidence source exists in the results.

Example:

- “practical solve times” -> runtime table
- “strategy front” -> TC9 and/or UAV three-strategy table
- “exact alternative to heuristics” -> either baseline comparison or softened language

### Workstream 4: Submission Tightening

#### Task 4.1 - Convert draft notes into paper text

Remove:

- figure placement notes
- drafting instructions
- meta commentary about future edits

Replace with:

- final captions
- normal paper prose

#### Task 4.2 - Page-budget compression

Prioritize keeping:

- introduction
- exact ASP method
- TC9 core results
- one strategy-comparison table
- one runtime table

Cut first if needed:

- extended scenario prose
- secondary topology figure
- non-essential discussion sentences

Deliverable:

- `SOCC_2026_Paper_Draft_v3.md`

## Recommended Execution Order

1. TC9 three-strategy evidence
2. runtime/scaling table
3. risk/objective method table
4. heuristic comparison decision
5. related-work expansion
6. manuscript v3 tightening

## Minimum Viable Fix Set

If time becomes tight, the minimum acceptable revision set is:

1. add TC9 three-strategy data
2. add runtime table
3. explicitly define the optimization objective
4. remove unsupported heuristic-superiority language

This is the smallest set of changes that materially reduces reviewer risk.

## Evidence-to-Claim Map

| Claim | Required Evidence | Current Status | Action |
|---|---|---|---|
| Exact SoC security synthesis | Phase 1 strategy results + optimality | Partial | complete TC9 front |
| Joint placement contribution | Phase 2 placements + excess privilege | Present | summarize more cleanly |
| Strategy-front comparison | Three-strategy table on primary case | Weak | generate TC9 table |
| Practical solve times | Runtime table | Missing | measure and add |
| Exact vs heuristic value | Baseline or softened claim | Weak | choose A or B |

## Current Recommendation

Proceed immediately with Workstream 1. The paper’s largest remaining weaknesses are quantitative support gaps, not conceptual gaps.
