"""The deterministic gate: a runner + one correctness oracle per security-behavior golden trace.

This is a **correctness oracle for security controls**, not a fuzzy quality score. A gated action
that auto-executes, a rejected action that still runs, a stale/replayed approval that authorizes
execution, or an org entity that leaks to a guest must each drop the aggregate score below
``MIN_PASS_SCORE`` and block the merge.

Every oracle drives the *real* compiled graph offline: a scripted planner, an
:class:`~langgraph.checkpoint.memory.InMemorySaver` (with the explicit ``atlas_serde()`` allowlist),
and a fresh :class:`~atlas.governance.InMemoryAuditLog`. Injecting both keeps the gate hermetic even
if ``DATABASE_URL`` happens to be set in the environment — the gate never touches Postgres.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.governance import InMemoryAuditLog
from atlas.governance.confidence import GROUNDED_ANSWER, UNGROUNDED_ANSWER
from atlas.governance.rbac import Principal
from atlas.knowledge import seed_demo_graph
from atlas.knowledge.interfaces import KnowledgeGraph
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from evals.deterministic.scenarios import (
    GUEST,
    MEMBER,
    empty_plan,
    search_plan,
    send_email_plan,
)

# Sentinel: "do not resume" (distinct from resuming with the falsy value ``False``).
_NO_RESUME = object()


@dataclass(frozen=True)
class OracleResult:
    """The outcome of one golden-trace oracle."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class Trace:
    """What the runner observed for one graph run."""

    paused: bool  # did the graph pause at the approval interrupt on the first invoke?
    final: dict[str, Any]  # final graph state
    audit_types: list[str]  # audit event-type values, in order


def _run(
    plan_fn: PlanFn,
    *,
    message: str,
    principal: Principal | None = None,
    knowledge: KnowledgeGraph | None = None,
    resume: Any = _NO_RESUME,
    thread_id: str = "eval",
) -> Trace:
    """Drive the real graph once (then optionally resume) and capture its behavior."""
    atlas = build_graph(
        plan_fn=plan_fn,
        audit=InMemoryAuditLog(),
        knowledge=knowledge,
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config = {"configurable": {"thread_id": thread_id}}
    first = atlas.graph.invoke(initial_state(message, principal=principal), config=config)
    paused = "__interrupt__" in first
    final = first
    if resume is not _NO_RESUME:
        final = atlas.graph.invoke(Command(resume=resume), config=config)
    audit_types = [event.event_type.value for event in atlas.audit.events()]
    return Trace(paused=paused, final=final, audit_types=audit_types)


# ---------------------------------------------------------------------------
# Oracles — one per HANDOFF §5a golden trace. Each returns an OracleResult.
# ---------------------------------------------------------------------------
def approval_approve() -> OracleResult:
    """Gated action pauses, then approve → the tool executes and is audited EXECUTED."""
    trace = _run(send_email_plan, message="email a@b.com", principal=MEMBER, resume=True)
    results = trace.final.get("action_results") or []
    passed = (
        trace.paused
        and len(results) == 1
        and results[0].ok is True
        and results[0].tool == "send_email"
        and "approved" in trace.audit_types
        and "executed" in trace.audit_types
    )
    return OracleResult("approval/approve", passed, f"audit={trace.audit_types}")


def approval_reject() -> OracleResult:
    """Gated action pauses, then reject → the tool is skipped, audited REJECTED, no fabricated result."""
    trace = _run(send_email_plan, message="email a@b.com", principal=MEMBER, resume=False)
    results = trace.final.get("action_results") or []
    passed = (
        trace.paused
        and results == []
        and "rejected" in trace.audit_types
        and "skipped" in trace.audit_types
        and "executed" not in trace.audit_types
    )
    return OracleResult("approval/reject", passed, f"audit={trace.audit_types}")


def anti_replay() -> OracleResult:
    """A resume carrying a wrong/stale action_id must NOT authorize the real action."""
    trace = _run(
        send_email_plan,
        message="email a@b.com",
        principal=MEMBER,
        resume=[{"action_id": "act_not_a_real_id", "approved": True}],
    )
    results = trace.final.get("action_results") or []
    passed = trace.paused and results == [] and "executed" not in trace.audit_types
    return OracleResult("anti-replay", passed, f"audit={trace.audit_types}")


def rbac_deny_before_approval() -> OracleResult:
    """A principal lacking the tool's permission is DENIED at planning — no interrupt, no execution."""
    trace = _run(send_email_plan, message="email a@b.com", principal=GUEST)
    results = trace.final.get("action_results") or []
    passed = (
        not trace.paused
        and results == []
        and "denied" in trace.audit_types
        and "approved" not in trace.audit_types
        and "executed" not in trace.audit_types
    )
    return OracleResult("rbac/deny-before-approval", passed, f"audit={trace.audit_types}")


def rbac_kg_idor() -> OracleResult:
    """An org-restricted entity a member sees must never reach a guest's context or cited sources."""
    query = "find the revenue and onboarding"
    member = _run(search_plan, message=query, principal=MEMBER, knowledge=seed_demo_graph())
    guest = _run(search_plan, message=query, principal=GUEST, knowledge=seed_demo_graph())

    member_kg = {entity.id for entity in (member.final.get("kg_context") or [])}
    guest_kg = {entity.id for entity in (guest.final.get("kg_context") or [])}
    member_src = {(s.kind, s.ref) for s in (member.final.get("sources") or [])}
    guest_src = {(s.kind, s.ref) for s in (guest.final.get("sources") or [])}

    passed = (
        "doc-1" in member_kg
        and "doc-1" not in guest_kg
        and ("knowledge", "doc-1") in member_src
        and ("knowledge", "doc-1") not in guest_src
    )
    return OracleResult("rbac/kg-idor", passed, f"member_kg={member_kg} guest_kg={guest_kg}")


def read_only_auto() -> OracleResult:
    """A read-only action runs with no interrupt and yields structured sources + a confidence."""
    trace = _run(search_plan, message="find the quarterly numbers", principal=MEMBER)
    results = trace.final.get("action_results") or []
    passed = (
        not trace.paused
        and len(results) == 1
        and results[0].ok is True
        and bool(trace.final.get("sources"))
        and trace.final.get("confidence") is not None
    )
    return OracleResult("read-only/auto", passed, f"confidence={trace.final.get('confidence')}")


def confidence_grounded_vs_ungrounded() -> OracleResult:
    """A grounded (knowledge-backed) answer must score strictly higher than an ungrounded one."""
    grounded = _run(empty_plan, message="revenue", principal=MEMBER, knowledge=seed_demo_graph())
    ungrounded = _run(empty_plan, message="something unrelated entirely", principal=MEMBER)

    grounded_conf = grounded.final.get("confidence")
    ungrounded_conf = ungrounded.final.get("confidence")
    passed = (
        grounded_conf == GROUNDED_ANSWER
        and ungrounded_conf == UNGROUNDED_ANSWER
        and grounded_conf > ungrounded_conf
    )
    return OracleResult(
        "confidence", passed, f"grounded={grounded_conf} ungrounded={ungrounded_conf}"
    )


# The full golden-trace suite. Order is informational only; scoring is order-independent.
ORACLES: tuple[Callable[[], OracleResult], ...] = (
    approval_approve,
    approval_reject,
    anti_replay,
    rbac_deny_before_approval,
    rbac_kg_idor,
    read_only_auto,
    confidence_grounded_vs_ungrounded,
)


def run_suite() -> tuple[float, list[OracleResult]]:
    """Run every oracle and return ``(score, results)`` where ``score`` is the pass ratio.

    Fail-closed: an oracle that raises is recorded as a failure (it never crashes the gate or, worse,
    silently passes). A score below ``MIN_PASS_SCORE`` makes :func:`evals.run_gate.main` exit non-zero.
    """
    results: list[OracleResult] = []
    for oracle in ORACLES:
        try:
            results.append(oracle())
        except Exception as exc:  # noqa: BLE001 - a crashing oracle is a failing oracle (fail-closed)
            results.append(
                OracleResult(oracle.__name__, False, f"raised {type(exc).__name__}: {exc}")
            )
    score = sum(1 for result in results if result.passed) / len(results)
    return score, results
