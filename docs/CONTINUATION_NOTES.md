# Continuation Notes — April 1, 2026

## Current State

**Branch:** `feat/dual-risk-budget` at commit `3cc12ea`
**Pushed to:** `origin/feat/dual-risk-budget`
**All papers and results are committed and pushed.**

---

## DASC 2026 Paper (deadline: April 25, 2026)

**File:** `docs/DASC_2026_Paper.tex` (617 lines, ~8 IEEE pages)
**Figures:** `fig3_tc9_topology.pdf`, `fig4_darpa_uav_topology.pdf` (+ TikZ workflow in .tex)
**References:** `docs/references.bib` (15 entries)

### Status: Near submission-ready

### Remaining work before submission:
1. **Compile in Overleaf** — upload .tex + .bib + 2 PDF figures, verify it fits 8 pages with float placement
2. **Proofread pass** — check for orphan sentences, table/figure placement, reference formatting
3. **Add author names** — currently anonymized for double-blind (`[Author names omitted]`)
4. **Verify figure quality** — SVG→PDF conversions may need re-export at higher resolution for print

### Known weaknesses (acceptable for submission):
- Comparison table (Table IV) is still somewhat lopsided ("Not in scope" for 5/10 Collins rows) — mitigated by caveat text
- No CP-SAT/MILP baseline — acknowledged explicitly in Discussion as planned future work
- TC9 balanced = min_resources (only 2 distinct optima) — explained in text but limits the "three-strategy" narrative

### Known bugs NOT in paper (safe):
- **Latency constraint is broken** in `opt_latency_enc.lp` — `selected_security(A, Security)` joins on asset name not component name, and no enforcement constraint exists. All latency claims removed from paper. Fix the solver if future papers need latency results.
- Phase 4 runtime adaptation encoding works but is cut from DASC scope (moved to future work)

---

## SOCC 2026 Paper (target: journal, no fixed deadline yet)

**File:** `docs/SOCC_2026_Paper_Draft_v5.md` (392 lines)
**PDF:** `docs/SOCC_2026_Paper_Draft_v5.pdf` (11 pages)

### Status: Strong draft, needs journal formatting

### Remaining work:
1. **Convert to LaTeX** — needs proper journal template (ACM or IEEE Transactions format)
2. **TC9 numbers use different IP catalog** than DASC — SOCC has zero_trust=1200 LUTs, DASC has 2100. Both are internally consistent but this MUST be documented if both papers are submitted
3. **Add the synthetic scaling sweep data** as supplementary material or appendix
4. **Latency claims still present** — lines 203, 205, 252 mention "latency-sensitive c8" and "latency-driven limits." These need the same fix as DASC (remove or qualify as "modeled but not enforced in current encoding")
5. **Needs co-author review** before submission

### Strengths to preserve:
- Honest "what evidence supports / does not support" structure (Section VII)
- Convergence trajectory table (Table IV-B) — unique contribution
- Synthetic scaling sweep (Table VI) — shows tractability boundary clearly

---

## Tool Development

### Priority fixes:
1. **Fix latency constraint bug** in `Clingo/opt_latency_enc.lp`:
   - Line 15: change `selected_security(A, Security)` to `selected_security(C, Security)` where C is component
   - Add enforcement constraint: `:- asset_latency(C, A, Op, Lat), allowable_latency(A, Op, Cap), Lat > Cap.`
   - Rerun TC9 and UAV to get actual latency-constrained results

2. **Phase 4 runtime adaptation** — works but needs integration test with Phase 1+2 context injection. Currently requires manual fact injection (`p1_logging/2`, `deployed_pep/1`, etc.)

3. **GUI network editor** — not tested recently, may have import issues after `phase3_agent.py` lazy import change

### Untracked debug files (safe to delete):
```
_debug_p1_balanced.lp
_debug_p1_max_security.lp
_debug_p1_min_resources.lp
_debug_refsoc_facts.lp
_debug_refsoc_gui_facts.lp
_gen_facts.py
_gen_facts2.py
```

---

## Scalability Results

**Directory:** `docs/scalability_results/`
**Source:** Colab run on Google Drive (`/content/drive/MyDrive/darpa_uav/HOST26_Code/`)

### Key result: UAV min_resources proven optimal
- 6 attempts, progressive timeout (60→120→300→600→1200→1800s)
- 37 models explored across attempts 1-4
- Final: risk=39, LUTs=8,410, 160mW — proven optimal
- Total wall time: 3,788s (~63 min)

---

## File Cleanup Recommendations

### Can delete (scratch/debug):
- `_debug_*.lp` — temporary solver debug dumps
- `_gen_facts*.py` — one-off fact generation scripts
- `docs/SOCC_2026_Paper_Draft.md` through `v4.md` — superseded by v5
- `docs/DASC_2026_Paper_Draft.md` — superseded by .tex
- `docs/DASC_2026_Paper_Merged_8Page.tex` / `_v2.tex` — superseded by DASC_2026_Paper.tex
- `docs/*_Plan.md`, `*_Revision_Plan.md` — planning artifacts, no longer needed

### Must keep:
- `docs/DASC_2026_Paper.tex` — THE submission file
- `docs/SOCC_2026_Paper_Draft_v5.md` — current SOCC draft
- `docs/references.bib` — shared bibliography
- `docs/fig*.pdf` — topology figures
- `docs/scalability_results/` — provenance for proven-optimal claim
- `docs/build_socc_pdf.py` — PDF builder for SOCC
- `docs/build_paper_pdf.py` — PDF builder for review drafts

---

## Conference Calendar

| Conference | Deadline | Paper |
|---|---|---|
| **DASC 2026** | **April 25, 2026** | DASC_2026_Paper.tex |
| SOCC 2026 | TBD (typically June-July) | SOCC_2026_Paper_Draft_v5.md |
| HOST 2026 | TBD (typically Jan-Feb 2027) | Future: latency + Phase 4 paper |
| DAC 2027 | TBD (typically Nov 2026) | Future: scalability paper |
