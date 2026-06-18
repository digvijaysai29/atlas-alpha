"""LangSmith evaluation gate for atlas.

This script is invoked by the `agent-eval` CI job (pull requests targeting `main`).

Golden-trace evaluation is an **M2** deliverable (see ARCHITECTURE.md §Roadmap). Until M2 lands
real golden datasets, this script fails OPEN (exits 0) when `LANGSMITH_API_KEY` is not configured,
so M1 pull requests are never blocked by an evaluation gate that has nothing to evaluate yet.

Once M2 wires up real golden traces, this script should:
  1. Pull the golden dataset(s) from LangSmith.
  2. Run the compiled graph (`atlas.orchestration.graph.build_graph`) against each example.
  3. Score the run (see TODO(M2) stubs below) and compare against `MIN_PASS_SCORE`.
  4. Exit non-zero (fail the `agent-eval` job, blocking merge) if the score is below threshold.

Security notes:
  - Never print or log the value of `LANGSMITH_API_KEY` or any other secret.
  - This script only *reads* env vars to decide whether to run; it must not require secrets to be
    present in order to execute safely (fail-closed on missing secrets means "skip", not "crash").
"""

from __future__ import annotations

import os
import sys

# Score threshold (0.0-1.0) that a golden-trace eval run must meet to pass the `agent-eval` CI gate
# once M2 golden datasets exist. Chosen to be strict enough to catch regressions in the approval
# gate (a false "auto-execute" on a gated action must always fail this threshold) while leaving
# room for benign scoring noise on the read-only search flow.
MIN_PASS_SCORE = 0.90


def _eval_gate_skipped(reason: str) -> None:
    """Print a clear, secret-free message explaining why the eval gate did not run."""
    print(f"[agent-eval] SKIPPED: {reason}")
    print(
        "[agent-eval] Golden traces land in M2 (see ARCHITECTURE.md §Roadmap). "
        "This is expected for M1 — not a failure."
    )


def main() -> int:
    """Entry point for the `agent-eval` CI job.

    Returns the process exit code: 0 to skip cleanly or to pass, non-zero to block the merge.
    """
    if not os.environ.get("LANGSMITH_API_KEY"):
        _eval_gate_skipped("LANGSMITH_API_KEY is not set")
        return 0

    # TODO(M2): Build/fetch golden trace dataset "atlas-approval-gate" in LangSmith covering:
    #   - A gated action (e.g. SEND/WRITE/DELETE/PAY tool call) that pauses on `interrupt()`.
    #   - The "approve" resume path: executor must run the tool and record an EXECUTED audit
    #     event; the response must reflect the tool's real output.
    #   - The "reject" resume path: executor must SKIP the tool entirely, record a REJECTED audit
    #     event, and the response must not fabricate a result for the rejected action.
    #   - An adversarial case: a stale/replayed ApprovalDecision (wrong action_id) must NOT
    #     authorize execution (anti-replay regression guard).
    #   Score each example pass/fail on "did the executor's behavior match the expected gate
    #   outcome" — this is a correctness oracle, not a fuzzy LLM-judge score, because the gate is
    #   a security control.

    # TODO(M2): Build/fetch golden trace dataset "atlas-readonly-search" covering:
    #   - A read-only query that should run automatically (RiskTier.READ) without any approval
    #     interrupt, returning sources + a confidence score in the final response.
    #   - A query where the planner can't find authoritative sources: response should surface low
    #     confidence rather than hide it (per CLAUDE.md "What Good Looks Like").
    #   Score with an LLM-judge rubric (faithfulness to sources, confidence calibration) averaged
    #   across the dataset; compare the mean score against MIN_PASS_SCORE.

    # TODO(M2): Replace this placeholder with the real evaluation run, e.g.:
    #     from langsmith import Client
    #     from langsmith.evaluation import evaluate
    #     results = evaluate(target_fn, data="atlas-approval-gate", evaluators=[...])
    #     score = summarize(results)
    #     if score < MIN_PASS_SCORE:
    #         print(f"[agent-eval] FAILED: score {score:.2f} < threshold {MIN_PASS_SCORE:.2f}")
    #         return 1
    print("[agent-eval] LANGSMITH_API_KEY is set, but golden datasets do not exist yet (M2).")
    print("[agent-eval] Nothing to evaluate — passing gate as a no-op for now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
