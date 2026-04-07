"""
phase1_mathopt_agent.py
=======================
Primary public entry point for Phase 1 mathematical optimisation.

This agent supports multiple backends:
- CP-SAT (default)
- CBC (optional)

The older ``ILPPhase1Agent`` name remains available from
``ilp_phase1_agent.py`` for compatibility.
"""

from .ilp_phase1_agent import Phase1MathOptAgent, ILPPhase1Agent

__all__ = ["Phase1MathOptAgent", "ILPPhase1Agent"]
