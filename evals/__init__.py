"""atlas evaluation gate.

A hybrid agent-eval gate (M2.3):

- :mod:`evals.deterministic` — a hermetic, **blocking** suite of security-behavior golden traces
  (no API key, no network); a failure drops the aggregate score below the threshold and blocks merge.
- :mod:`evals.llm_judge` — an optional, **non-blocking** LangSmith LLM-judge layer that runs only
  when ``LANGSMITH_API_KEY`` is set and never changes the gate's exit code (telemetry, not a control).

:mod:`evals.run_gate` is the entrypoint invoked by the ``agent-eval`` CI job.
"""
