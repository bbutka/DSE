# Legacy Quarantine

This directory holds standalone artifacts that are no longer part of the
integrated `DSE_Core` package flow.

Quarantined here:
- `runners/runClingo.py`
- `runners/runClingo_tc9.py`
- `runners/runClingo_darpa_uav.py`
- `Clingo/resilience_tc9_enc.lp`
- `testCases/testCase9_inst.lp`

These files are retained only for historical reference and manual
comparison. The active integrated path is:

1. Phase 1: `dse_tool.agents.ilp_phase1_agent.ILPPhase1Agent`
2. Phase 1 fallback: `dse_tool.agents.phase1_agent.Phase1Agent`
3. Phase 2: `Clingo/zta_policy_enc.lp`
4. Phase 3: `Clingo/resilience_enc.lp`

The GUI and orchestrator should not depend on anything in this folder.
