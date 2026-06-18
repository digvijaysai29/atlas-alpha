# Evaluation Gate

This directory holds the **LangSmith evaluation gate** for atlas's agent orchestration graph. It
is run by the `agent-eval` job in `.github/workflows/ci.yml`, which executes only on pull requests
targeting `main`.

## Purpose

The eval gate exists to catch regressions in security-critical agent behavior that unit tests
don't cover end-to-end — in particular, whether the **HITL approval gate** behaves correctly
across full graph runs (not just isolated policy-function calls), and whether the **read-only
search** flow produces well-sourced, appropriately-confident answers.

This is a **correctness oracle for the gate**, not a vibes-based LLM quality score: a gated action
that gets auto-executed, or a rejected action that still runs, must always fail this gate.

## Current status (M1)

Golden trace datasets do not exist yet. Building them is an **M2** deliverable (see
[`ARCHITECTURE.md`](../ARCHITECTURE.md) §Roadmap — "RBAC; Knowledge Graph interface wired into the
planner; confidence/source maturation; simple gate-correctness evaluation hooks").

Until then, `run_evals.py`:

1. Checks for `LANGSMITH_API_KEY`. If it is **not set**, the script prints a clear
   `SKIPPED` message and exits `0` — the `agent-eval` CI job passes without blocking the PR.
2. If the key **is** set but no golden dataset exists yet, it currently still passes as a no-op
   (this will change once M2 datasets are built — see the `TODO(M2)` markers in the script).

This means the gate is safe to leave wired into CI today: it never fails a PR for a missing M2
deliverable, but it's ready to start enforcing real evaluation as soon as the datasets exist.

## Adding golden datasets in M2

1. Record real (or carefully hand-built) LangGraph traces for the two flows below and upload them
   to LangSmith as named datasets:
   - **`atlas-approval-gate`** — covers a gated action's full lifecycle: proposal → `interrupt()`
     → approve (executor runs the tool, audit gets an `EXECUTED` event) and → reject (executor
     skips the tool, audit gets a `REJECTED` event, no fabricated result). Include an adversarial
     case where a stale/replayed `ApprovalDecision` (wrong `action_id`) must **not** authorize
     execution.
   - **`atlas-readonly-search`** — covers a `RiskTier.READ` query that runs automatically (no
     interrupt) and returns a response with `sources` and a `confidence` score, including a
     low-confidence case that must be surfaced, not hidden.
2. Replace the placeholder logic in `run_evals.py` (see the `TODO(M2)` comments) with a real
   `langsmith.evaluation.evaluate(...)` call against `atlas.orchestration.graph.build_graph()`.
3. Score the approval-gate dataset with a deterministic correctness oracle (did the executor do
   exactly what the expected outcome says), and the search dataset with whatever
   faithfulness/confidence-calibration rubric the team settles on.
4. Compare the result against `MIN_PASS_SCORE` in `run_evals.py` (currently `0.90`) and return a
   non-zero exit code on failure so the `agent-eval` CI job blocks the merge.

## Running locally

```bash
# Without LANGSMITH_API_KEY set: prints a SKIPPED message and exits 0.
uv run python evals/run_evals.py

# With LANGSMITH_API_KEY set (once M2 datasets exist): runs the real evaluation.
LANGSMITH_API_KEY=... uv run python evals/run_evals.py
```

## Which CI job runs this

The `agent-eval` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), gated to
`pull_request` events targeting `main` only. It never echoes the value of any secret.
