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

from atlas.actions import ProposedAction
from atlas.execution import GuardedExecutor
from atlas.governance import AuditEventType, InMemoryAuditLog, InMemoryPolicyStore
from atlas.governance.confidence import GROUNDED_ANSWER, UNGROUNDED_ANSWER
from atlas.governance.rbac import Principal
from atlas.knowledge import (
    IngestDocument,
    IngestionDenied,
    IngestionService,
    InMemoryKnowledgeGraph,
    seed_demo_graph,
)
from atlas.knowledge.interfaces import KnowledgeGraph
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry
from tests.helpers import FakeEmailSender, offline_registry
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
        registry=offline_registry(),
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


def _approved_send(registry: ToolRegistry) -> ProposedAction:
    return registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})


def idempotency_replay_skip() -> OracleResult:
    """Double ``execute_guarded`` on the same action → one EXECUTED, one REPLAY_SKIPPED."""
    sender = FakeEmailSender()
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_send(registry)

    principal = Principal(user_id="test", roles=("member",), org_id="org1")

    first = guarded.execute_guarded(action, audit, principal)
    second = guarded.execute_guarded(action, audit, principal)

    event_types = [e.event_type for e in audit.events()]
    passed = (
        sender.call_count == 1
        and first.ok is True
        and second.ok is True
        and isinstance(second.output, dict)
        and second.output.get("replay_skipped") is True
        and event_types.count(AuditEventType.EXECUTED) == 1
        and AuditEventType.REPLAY_SKIPPED in event_types
    )
    audit_detail = [e.event_type.value for e in audit.events()]
    return OracleResult(
        "idempotency/replay-skip", passed, f"audit={audit_detail} calls={sender.call_count}"
    )


def idempotency_failed_retry() -> OracleResult:
    """Failed send → FAILED (not EXECUTED); retry after recovery → EXECUTED."""
    sender = FakeEmailSender(fail=True)
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_send(registry)

    principal = Principal(user_id="test", roles=("member",), org_id="org1")

    first = guarded.execute_guarded(action, audit, principal)
    sender.fail = False
    second = guarded.execute_guarded(action, audit, principal)

    event_types = [e.event_type for e in audit.events()]
    passed = (
        first.ok is False
        and second.ok is True
        and sender.call_count == 2
        and AuditEventType.FAILED in event_types
        and event_types.count(AuditEventType.EXECUTED) == 1
    )
    audit_detail = [e.event_type.value for e in audit.events()]
    return OracleResult(
        "idempotency/failed-retry", passed, f"audit={audit_detail} calls={sender.call_count}"
    )


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


# ---------------------------------------------------------------------------
# Ingestion oracles (M4.4) — the KG *write* path. Hermetic: drive the IngestionService + in-memory KG
# directly, no graph/LLM/network. These guard PKG isolation, dedup/idempotency, and OKG-write authz.
# ---------------------------------------------------------------------------
_ALICE = Principal(user_id="alice", roles=("member",))
_BOB = Principal(user_id="bob", roles=("member",))
_ADMIN = Principal(user_id="root", roles=("admin",))


def ingest_pkg_isolation() -> OracleResult:
    """A personal doc Alice ingests is visible to Alice and invisible to Bob (PKG isolation / IDOR)."""
    kg = InMemoryKnowledgeGraph()
    service = IngestionService(kg, InMemoryPolicyStore())
    service.ingest(
        _ALICE, IngestDocument(text="alice onboarding plan", title="plan", scope="personal")
    )

    alice_ids = {entity.id for entity in kg.query(_ALICE, "onboarding")}
    bob_ids = {entity.id for entity in kg.query(_BOB, "onboarding")}
    passed = bool(alice_ids) and not bob_ids and not (alice_ids & bob_ids)
    return OracleResult("ingest/pkg-isolation", passed, f"alice={alice_ids} bob={bob_ids}")


def ingest_dedup_idempotent() -> OracleResult:
    """Re-ingesting the same document is idempotent — same ids, no duplicate growth."""
    kg = InMemoryKnowledgeGraph()
    service = IngestionService(kg, InMemoryPolicyStore())
    document = IngestDocument(text="repeatable content", title="dup", scope="personal")

    first = service.ingest(_ALICE, document)
    count_after_first = len(kg.query(_ALICE, "", limit=1000))
    second = service.ingest(_ALICE, document)
    count_after_second = len(kg.query(_ALICE, "", limit=1000))

    passed = (
        first.entity_ids == second.entity_ids
        and count_after_first == count_after_second
        and count_after_first == len(first.entity_ids)
    )
    return OracleResult(
        "ingest/dedup-idempotent", passed, f"first={count_after_first} second={count_after_second}"
    )


def ingest_okg_write_denied() -> OracleResult:
    """A member's org write is denied (nothing written); an admin's org write succeeds and is org-readable."""
    kg = InMemoryKnowledgeGraph()
    service = IngestionService(kg, InMemoryPolicyStore())
    org_doc = IngestDocument(text="org wide policy", title="policy", scope="org")

    denied = False
    try:
        service.ingest(_ALICE, org_doc)
    except IngestionDenied:
        denied = True
    nothing_written = len(kg.query(_ADMIN, "", limit=1000)) == 0

    admin_result = service.ingest(_ADMIN, org_doc)
    member_can_read_org = bool(kg.query(_ALICE, "policy"))

    passed = denied and nothing_written and bool(admin_result.entity_ids) and member_can_read_org
    return OracleResult(
        "ingest/okg-write-denied", passed, f"denied={denied} admin_wrote={admin_result.entity_ids}"
    )


# The full golden-trace suite. Order is informational only; scoring is order-independent.
ORACLES: tuple[Callable[[], OracleResult], ...] = (
    approval_approve,
    approval_reject,
    anti_replay,
    idempotency_replay_skip,
    idempotency_failed_retry,
    rbac_deny_before_approval,
    rbac_kg_idor,
    read_only_auto,
    confidence_grounded_vs_ungrounded,
    ingest_pkg_isolation,
    ingest_dedup_idempotent,
    ingest_okg_write_denied,
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
