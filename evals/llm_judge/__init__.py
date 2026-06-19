"""Optional, non-blocking LangSmith LLM-judge layer.

This layer is **telemetry, not a security control**: it runs only when ``LANGSMITH_API_KEY`` is set,
scores softer qualities of the read-only flow (source faithfulness, confidence calibration), logs
traces/experiments to LangSmith for dashboards, and **never** changes the gate's exit code. A
LangSmith outage (or a missing ``ANTHROPIC_API_KEY`` for the judge) must never fail a correct PR.
"""

from evals.llm_judge.judge import run_llm_judge

__all__ = ["run_llm_judge"]
