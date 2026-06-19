"""LangSmith dataset definitions for the non-blocking quality evals.

Two named datasets back the LangSmith dashboards (HANDOFF §5b). They are created idempotently —
on a fresh project they are created and seeded; if they already exist they are reused as-is (we do
not mutate or delete existing examples, so re-runs are safe). All of this is best-effort: any
failure is swallowed by the caller in :mod:`evals.llm_judge.judge`.

The example *inputs* are user requests; the *outputs* are lightweight reference expectations the
deterministic calibration evaluator can check (an LLM judge scores the softer "faithfulness").
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from langsmith import Client

# Dataset names are stable identifiers referenced by CI dashboards and `evaluate(data=...)`.
DATASET_READONLY = "atlas-readonly-search"
DATASET_APPROVAL = "atlas-approval-gate"

# Read-only golden inputs + reference expectations. ``expect_source`` means the answer must cite at
# least one source; ``min_confidence`` is the floor the responder's confidence should clear.
_READONLY_EXAMPLES: list[dict[str, Any]] = [
    {
        "inputs": {"request": "find the quarterly revenue numbers"},
        "outputs": {"expect_source": True, "min_confidence": 0.5},
    },
    {
        "inputs": {"request": "look up the onboarding checklist"},
        "outputs": {"expect_source": True, "min_confidence": 0.5},
    },
    {
        "inputs": {"request": "what do we know about revenue and onboarding"},
        "outputs": {"expect_source": True, "min_confidence": 0.5},
    },
]

# A small descriptive companion dataset for the approval flow (dashboards/telemetry only; the
# blocking correctness checks for this flow live in `evals.deterministic`).
_APPROVAL_EXAMPLES: list[dict[str, Any]] = [
    {
        "inputs": {"request": "email a@b.com the status update", "decision": "approve"},
        "outputs": {"expect_executed": True},
    },
    {
        "inputs": {"request": "email a@b.com the status update", "decision": "reject"},
        "outputs": {"expect_executed": False},
    },
]


def _ensure_dataset(
    client: "Client", name: str, description: str, examples: list[dict[str, Any]]
) -> None:
    """Create + seed a dataset if it does not already exist; otherwise leave it untouched."""
    if client.has_dataset(dataset_name=name):
        return
    dataset = client.create_dataset(name, description=description)
    client.create_examples(
        inputs=[example["inputs"] for example in examples],
        outputs=[example["outputs"] for example in examples],
        dataset_id=dataset.id,
    )


def ensure_datasets(client: "Client") -> None:
    """Idempotently ensure both telemetry datasets exist (best-effort; caller swallows errors)."""
    _ensure_dataset(
        client,
        DATASET_READONLY,
        "atlas read-only search flow: well-sourced, appropriately-confident answers.",
        _READONLY_EXAMPLES,
    )
    _ensure_dataset(
        client,
        DATASET_APPROVAL,
        "atlas HITL approval flow (telemetry; blocking checks live in evals.deterministic).",
        _APPROVAL_EXAMPLES,
    )
