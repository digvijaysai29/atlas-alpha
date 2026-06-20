"""Interface integration test (run only when DATABASE_URL is set).

Proves the HTTP layer's resume flow is durable AND that resume-time principal/thread binding survives
a simulated process restart: a thread Alice starts in one app instance can only be resumed by Alice
(not Bob) in a brand-new app instance reading from Postgres.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.interface import create_app
from atlas.orchestration import build_graph
from atlas.orchestration.graph import _pg_pool
from atlas.tools import ToolRegistry

from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _settings(url: str) -> Settings:
    return Settings(DATABASE_URL=SecretStr(url), ANTHROPIC_API_KEY=None)


def _headers(user: str) -> dict[str, str]:
    return {"X-Atlas-User-Id": user, "X-Atlas-Roles": "member"}


def test_thread_resume_is_durable_and_owner_bound_across_restart(database_url: str) -> None:
    settings = _settings(database_url)

    # First "process": Alice starts a send; the graph pauses at approval (state lives in Postgres).
    _pg_pool.cache_clear()
    client1 = TestClient(create_app(atlas=build_graph(plan_fn=_send_plan, settings=settings)))
    started = client1.post("/chat", json={"message": "email a@b.com"}, headers=_headers("alice"))
    thread_id = started.json()["thread_id"]
    assert started.json()["status"] == "awaiting_approval"
    del client1
    _pg_pool.cache_clear()  # drop the cached pool so the next app opens fresh connections

    # Second "process": a brand-new app over the same DB.
    client2 = TestClient(create_app(atlas=build_graph(plan_fn=_send_plan, settings=settings)))
    # Binding survives the restart: Bob cannot approve Alice's pending action.
    assert (
        client2.post(
            "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("bob")
        ).status_code
        == 403
    )
    # The owner resumes from Postgres and the action executes.
    out = client2.post(
        "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("alice")
    ).json()
    assert out["status"] == "completed"
    assert out["action_results"][0]["ok"] is True
