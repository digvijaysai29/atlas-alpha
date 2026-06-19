"""Deterministic, blocking gate — hermetic correctness oracles for atlas's security controls.

Each golden trace is **data** (input + principal + resume decision + expected outcome). The runner
in :mod:`evals.deterministic.oracles` drives the *real* compiled graph fully offline (scripted
planner + in-memory checkpointer + in-memory audit) and asserts the exact gate behavior. The
aggregate pass ratio is compared against ``MIN_PASS_SCORE`` by :mod:`evals.run_gate`.
"""

from evals.deterministic.oracles import OracleResult, run_suite

__all__ = ["OracleResult", "run_suite"]
