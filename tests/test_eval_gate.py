"""Meta-tests for the M2.3 deterministic agent-eval gate.

Two properties matter: (1) on a healthy graph every security oracle passes (so the gate doesn't
flake and block good PRs), and (2) the aggregator actually *discriminates* — a failing or crashing
oracle drops the score below the merge threshold (so a real regression is caught). Both run offline.
"""

import pytest

from evals.deterministic import OracleResult, run_suite
from evals.deterministic import oracles as oracles_module
from evals.deterministic.oracles import approval_approve
from evals.run_gate import MIN_PASS_SCORE


def test_healthy_suite_scores_perfect() -> None:
    score, results = run_suite()
    assert score == 1.0
    assert score >= MIN_PASS_SCORE
    assert all(result.passed for result in results), [r for r in results if not r.passed]
    # The full HANDOFF §5a golden-trace set is present.
    assert {result.name for result in results} == {
        "approval/approve",
        "approval/reject",
        "anti-replay",
        "rbac/deny-before-approval",
        "rbac/kg-idor",
        "read-only/auto",
        "confidence",
    }


def test_approve_oracle_passes_on_real_graph() -> None:
    assert approval_approve().passed is True


def test_run_suite_fails_closed_on_failing_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing oracle must pull the aggregate score below the merge threshold."""

    def _always_fails() -> OracleResult:
        return OracleResult("synthetic/regression", passed=False, detail="injected")

    monkeypatch.setattr(oracles_module, "ORACLES", (approval_approve, _always_fails), raising=True)
    score, results = run_suite()
    assert score == 0.5
    assert score < MIN_PASS_SCORE
    assert any(r.name == "synthetic/regression" and not r.passed for r in results)


def test_run_suite_treats_a_crashing_oracle_as_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A crashing oracle is recorded as a failure, never silently passed (fail-closed)."""

    def _boom() -> OracleResult:
        raise RuntimeError("oracle blew up")

    monkeypatch.setattr(oracles_module, "ORACLES", (approval_approve, _boom), raising=True)
    score, results = run_suite()
    assert score == 0.5
    crashed = next(r for r in results if r.name == "_boom")
    assert crashed.passed is False
    assert "RuntimeError" in crashed.detail
