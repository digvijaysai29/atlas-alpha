"""SSE streaming interface tests (offline, hermetic via FastAPI TestClient).

Mirrors ``test_interface.py``: each app is built with an injected test ``Atlas`` (InMemorySaver + a
scripted plan) so no API key, network, or Postgres is needed. The headline assertions are that the
**same security spine as ``/chat`` holds for ``/chat/stream``** — identity (401) and rate limiting
(429) are enforced *before* any event streams — and that a mid-stream failure surfaces a single
**generic** ``error`` event without leaking internals.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import StateSnapshot

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.auth import OidcAuthenticator
from atlas.interface.rate_limit import RateLimiter, RateLimitDecision
from atlas.interface.routes import _config, _response_from_snapshot
from atlas.interface.sse import run_graph_stream
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry

import anyio
from fastapi.testclient import TestClient


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _search_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def _boom_plan(_req: str, _registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    raise RuntimeError("secret-internal-detail-should-not-leak")


class _DenyLimiter(RateLimiter):
    """A limiter that always rejects — exercises the 429-before-stream path."""

    def acquire(self, key: str) -> RateLimitDecision:
        return RateLimitDecision(allowed=False, retry_after=1.0)


def _unverified_authenticator() -> OidcAuthenticator:
    """An authenticator whose signing key is never consulted — a missing token 401s before that."""
    return OidcAuthenticator(
        issuer="https://issuer.test/", audience="atlas-api", get_signing_key=lambda _token: None
    )


def _build(
    plan_fn: PlanFn,
    *,
    settings: Settings | None = None,
    authenticator: OidcAuthenticator | None = None,
    rate_limiter: RateLimiter | None = None,
) -> tuple[TestClient, Atlas]:
    atlas = build_graph(
        plan_fn=plan_fn,
        registry=offline_registry(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    app = create_app(
        atlas=atlas,
        settings=settings or Settings(ANTHROPIC_API_KEY=None),
        authenticator=authenticator,
        rate_limiter=rate_limiter,
    )
    return TestClient(app), atlas


def _headers(user: str, roles: str = "member", org: str | None = None) -> dict[str, str]:
    h = {"X-Atlas-User-Id": user, "X-Atlas-Roles": roles}
    if org is not None:
        h["X-Atlas-Org"] = org
    return h


def _parse_sse(text: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse an SSE body into ``(event, data)`` pairs, ignoring keep-alive comment lines."""
    events: list[tuple[str, dict[str, Any]]] = []
    event: str | None = None
    data_parts: list[str] = []
    for line in text.splitlines():
        if line.startswith("event:"):
            event = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_parts.append(line[len("data:") :].strip())
        elif line == "":
            if event is not None:
                raw = "".join(data_parts)
                events.append((event, json.loads(raw) if raw else {}))
            event, data_parts = None, []
    if event is not None:  # trailing event with no blank terminator
        raw = "".join(data_parts)
        events.append((event, json.loads(raw) if raw else {}))
    return events


def _stream(
    client: TestClient, headers: dict[str, str], message: str = "go"
) -> list[tuple[str, dict[str, Any]]]:
    resp = client.post("/chat/stream", json={"message": message}, headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    return _parse_sse(resp.text)


# --- happy paths -------------------------------------------------------------
def test_read_only_turn_streams_open_then_completed_then_done() -> None:
    client, _ = _build(_search_plan)
    events = _stream(client, _headers("alice"), "find things")
    names = [e for e, _ in events]
    assert names[0] == "open"
    assert names[-1] == "done"
    assert "node" in names
    completed = [data for e, data in events if e == "completed"]
    assert completed, "a read-only turn must end in a completed event"
    assert completed[0]["status"] == "completed"
    assert completed[0]["confidence"] is not None
    assert "awaiting_approval" not in names


def test_send_turn_streams_awaiting_approval_and_no_completed() -> None:
    client, _ = _build(_send_plan)
    events = _stream(client, _headers("alice"), "email a@b.com")
    names = [e for e, _ in events]
    assert "awaiting_approval" in names
    assert "completed" not in names
    assert names[-1] == "done"
    pending = next(data for e, data in events if e == "awaiting_approval")["pending_actions"]
    assert pending[0]["tool"] == "send_email"


def test_node_events_carry_name_only_no_action_payload() -> None:
    client, _ = _build(_send_plan)
    events = _stream(client, _headers("alice"), "email a@b.com")
    node_payloads = [data for e, data in events if e == "node"]
    assert node_payloads, "expected at least one node progress event"
    # A node event exposes the node name and nothing else (no proposed-action content).
    assert all(set(p.keys()) == {"node"} for p in node_payloads)


# --- security: authn / rate-limit run BEFORE the stream body -----------------
def test_missing_bearer_token_is_401_before_any_event() -> None:
    client, _ = _build(_search_plan, authenticator=_unverified_authenticator())
    resp = client.post("/chat/stream", json={"message": "find"})  # no Authorization header
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["ok"] is False


def test_rate_limited_is_429_before_any_event() -> None:
    client, _ = _build(_search_plan, rate_limiter=_DenyLimiter())
    resp = client.post("/chat/stream", json={"message": "find"}, headers=_headers("alice"))
    assert resp.status_code == 429
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers.get("Retry-After") is not None


# --- security: mid-stream failure degrades to a generic error event ----------
def test_mid_stream_failure_emits_generic_error_without_leaking() -> None:
    client, _ = _build(_boom_plan)
    resp = client.post("/chat/stream", json={"message": "go"}, headers=_headers("alice"))
    assert resp.status_code == 200
    assert "secret-internal-detail-should-not-leak" not in resp.text
    events = _parse_sse(resp.text)
    names = [e for e, _ in events]
    assert names[0] == "open"
    assert "error" in names
    assert names[-1] == "done"
    assert "completed" not in names
    error = next(data for e, data in events if e == "error")
    assert error == {"code": "internal_error", "message": "Internal server error."}


# --- OpenAPI contract --------------------------------------------------------
def test_chat_stream_openapi_documents_text_event_stream() -> None:
    client, _ = _build(_search_plan)
    content = client.get("/openapi.json").json()["paths"]["/chat/stream"]["post"]["responses"][
        "200"
    ]["content"]
    assert "text/event-stream" in content
    assert "application/json" not in content


# --- producer drain on consumer detach -----------------------------------------
async def test_consumer_detach_drains_graph_to_completion() -> None:
    client, atlas = _build(_search_plan)
    thread_id = f"thr_{uuid.uuid4().hex}"
    config = _config(thread_id)
    principal = Principal(user_id="alice", roles=("member",))

    send_stream, receive_stream = anyio.create_memory_object_stream(max_buffer_size=16)
    producer_task = asyncio.create_task(
        run_graph_stream(
            atlas.graph,
            initial_state("find things", principal=principal),
            config,
            send_stream,
        )
    )
    try:
        async with receive_stream:
            async for _chunk in receive_stream:
                break
    finally:
        await receive_stream.aclose()
        await producer_task

    snapshot = atlas.graph.get_state(config)
    assert not snapshot.next

    resp = client.get(f"/threads/{thread_id}", headers=_headers("alice"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["response"] is not None


# --- in_progress snapshot shaping ----------------------------------------------
def test_in_progress_snapshot_returns_minimal_response() -> None:
    snapshot = StateSnapshot(
        values={"messages": []},
        next=("responder",),
        config={},
        metadata=None,
        created_at=None,
        parent_config=None,
        tasks=(),
        interrupts=(),
    )
    response = _response_from_snapshot("thr_test", snapshot)
    assert response.status == "in_progress"
    assert response.thread_id == "thr_test"
    assert response.response is None
