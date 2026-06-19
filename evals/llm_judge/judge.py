"""The optional, non-blocking LangSmith LLM-judge run.

``run_llm_judge`` is the single entrypoint. It is **best-effort**: every failure path is swallowed
and logged secret-free, and it always returns ``None`` (it can never change the gate's exit code).

What it does when ``LANGSMITH_API_KEY`` is set:
  1. Idempotently ensure the telemetry datasets exist.
  2. Run the *real* graph (offline, heuristic planner) over the read-only dataset as the target.
  3. Score each row with a deterministic **confidence-calibration** evaluator and — only when an
     ``ANTHROPIC_API_KEY`` is available — an LLM **source-faithfulness** judge.
  4. Upload the experiment to LangSmith for dashboards.

Security: the LangSmith key is read from the environment by the ``Client`` itself; this module never
reads, prints, or logs it (or any other secret). On error we log only the exception *type*.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langgraph.checkpoint.memory import InMemorySaver

from atlas.config import get_settings
from atlas.governance.rbac import Principal
from atlas.knowledge import seed_demo_graph
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import heuristic_plan
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from evals.llm_judge.datasets import DATASET_READONLY, ensure_datasets

if TYPE_CHECKING:
    from langsmith.schemas import Example, Run

# The principal the telemetry target runs as: a member who may read org + personal knowledge.
_TARGET_PRINCIPAL = Principal(user_id="eval-judge", roles=("member",))

_JUDGE_SYSTEM = (
    "You are grading whether an assistant's answer is faithful to the sources it cites. "
    "Respond with a single number between 0 and 1: 1.0 if every claim is supported by the listed "
    "sources, 0.0 if the answer asserts facts with no supporting source. Output only the number."
)


def _run_graph(request: str) -> dict[str, Any]:
    """Run the real graph offline for one request; return the answer text, sources, confidence."""
    atlas = build_graph(
        plan_fn=heuristic_plan,
        knowledge=seed_demo_graph(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config = {"configurable": {"thread_id": "llm-judge"}}
    final = atlas.graph.invoke(initial_state(request, principal=_TARGET_PRINCIPAL), config=config)
    messages = final.get("messages") or []
    answer = str(getattr(messages[-1], "content", "")) if messages else ""
    sources = [f"{source.kind}:{source.ref}" for source in (final.get("sources") or [])]
    return {"answer": answer, "sources": sources, "confidence": final.get("confidence")}


def _target(inputs: dict[str, Any]) -> dict[str, Any]:
    """LangSmith target: map a dataset input to the graph's structured output."""
    return _run_graph(str(inputs.get("request", "")))


def _confidence_calibration(run: "Run", example: "Example") -> dict[str, Any]:
    """Deterministic: did the answer clear the reference confidence floor and cite a source?"""
    outputs = run.outputs or {}
    expected = example.outputs or {}
    confidence = outputs.get("confidence")
    floor = expected.get("min_confidence", 0.0)
    has_source = bool(outputs.get("sources")) if expected.get("expect_source") else True
    calibrated = confidence is not None and confidence >= floor and has_source
    return {"key": "confidence_calibration", "score": int(calibrated)}


def _source_faithfulness(run: "Run", example: "Example") -> dict[str, Any]:
    """LLM judge: is the answer grounded in the sources it cites? (Skipped without an Anthropic key.)"""
    del example  # the judge grades the answer-vs-sources pair, not the reference expectation
    settings = get_settings()
    if not settings.has_anthropic_key:
        return {"key": "source_faithfulness", "score": None, "comment": "no anthropic key; skipped"}
    from atlas.llm import build_model

    outputs = run.outputs or {}
    answer = str(outputs.get("answer", ""))
    sources = ", ".join(outputs.get("sources", [])) or "(none)"
    model = build_model(settings)
    reply = model.invoke(
        [("system", _JUDGE_SYSTEM), ("human", f"Sources: {sources}\n\nAnswer: {answer}")]
    )
    try:
        score = max(0.0, min(1.0, float(str(reply.content).strip().split()[0])))
    except (ValueError, IndexError):
        score = 0.0
    return {"key": "source_faithfulness", "score": score}


def run_llm_judge() -> None:
    """Run the non-blocking LangSmith quality evals. Never raises; never affects the exit code."""
    try:
        from langsmith import Client, evaluate

        client = Client()
        ensure_datasets(client)
        results = evaluate(
            _target,
            data=DATASET_READONLY,
            evaluators=[_confidence_calibration, _source_faithfulness],
            experiment_prefix="atlas-readonly",
            metadata={"gate": "m2.3", "blocking": False},
        )
        name = getattr(results, "experiment_name", DATASET_READONLY)
        print(f"[llm-judge] LangSmith experiment uploaded: {name} (non-blocking telemetry).")
    except Exception as exc:  # noqa: BLE001 - telemetry must never break the gate; log type only
        print(f"[llm-judge] skipped (non-blocking): {type(exc).__name__}.")
