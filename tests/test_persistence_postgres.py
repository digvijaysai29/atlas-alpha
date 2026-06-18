"""Postgres integration tests (run only when DATABASE_URL is set).

Proves the two M2.1 guarantees end-to-end:
1. A pending approval survives a simulated process restart (resumed from Postgres).
2. The Postgres audit log is hash-chained and tamper-evident.
"""

from __future__ import annotations

import uuid

import pytest
from langgraph.types import Command
from pydantic import SecretStr

from atlas.actions import ActionResult, ApprovalDecision, ProposedAction
from atlas.config import Settings
from atlas.orchestration import build_graph
from atlas.orchestration.graph import _pg_pool
from atlas.orchestration.state import initial_state
from atlas.persistence import PostgresAuditLog
from atlas.tools import ToolRegistry, default_registry

pytestmark = pytest.mark.integration


def _settings(url: str) -> Settings:
    return Settings(DATABASE_URL=SecretStr(url), ANTHROPIC_API_KEY=None)


def _send_plan(_request: str, registry: ToolRegistry) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def test_pending_approval_survives_a_simulated_restart(database_url: str) -> None:
    settings = _settings(database_url)
    thread = {"configurable": {"thread_id": f"it-{uuid.uuid4().hex[:8]}"}}

    # First process: run until the approval interrupt, then "crash".
    _pg_pool.cache_clear()
    atlas1 = build_graph(plan_fn=_send_plan, settings=settings)
    paused = atlas1.graph.invoke(initial_state("email a@b.com"), config=thread)
    assert "__interrupt__" in paused
    del atlas1
    _pg_pool.cache_clear()  # drop the cached pool so the next graph opens fresh connections

    # Second process: a brand-new graph on the same DB resumes the pending approval.
    atlas2 = build_graph(plan_fn=_send_plan, settings=settings)
    final = atlas2.graph.invoke(Command(resume=True), config=thread)

    results = final["action_results"]
    assert len(results) == 1
    assert results[0].ok is True
    assert results[0].tool == "send_email"


def test_postgres_audit_is_hash_chained_and_tamper_evident(pg_pool: object) -> None:
    log = PostgresAuditLog(pg_pool)  # type: ignore[arg-type]
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com"})

    log.proposed(action)
    log.decided(ApprovalDecision(action_id=action.action_id, approved=True))
    log.executed(
        ActionResult(action_id=action.action_id, tool="send_email", ok=True, output="sent")
    )

    # A fresh store instance reads the persisted chain and verifies it.
    reloaded = PostgresAuditLog(pg_pool, setup=False)  # type: ignore[arg-type]
    assert len(reloaded.events()) == 3
    assert reloaded.verify().ok is True

    # Tamper directly in the database -> verification must fail.
    with pg_pool.connection() as conn:  # type: ignore[attr-defined]
        conn.execute("UPDATE atlas_audit_log SET actor = 'attacker' WHERE seq = 0")
    assert reloaded.verify().ok is False
