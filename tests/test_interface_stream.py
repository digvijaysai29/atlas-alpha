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


# --- /approve/stream (M4.8d) ---------------------------------------------------
def _stream_approve(
    client: TestClient, thread_id: str, headers: dict[str, str], *, approve: bool
) -> Any:
    return client.post(
        "/approve/stream",
        json={"thread_id": thread_id, "approve": approve},
        headers=headers,
    )


def test_approve_stream_happy_path_resumes_and_completes() -> None:
    client, _ = _build(_send_plan)
    chat_resp = client.post("/chat", json={"message": "email a@b.com"}, headers=_headers("alice"))
    assert chat_resp.json()["status"] == "awaiting_approval"
    thread_id = chat_resp.json()["thread_id"]

    resp = _stream_approve(client, thread_id, _headers("alice"), approve=True)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    events = _parse_sse(resp.text)
    names = [e for e, _ in events]
    assert names[0] == "open"
    assert names[-1] == "done"
    completed = next(data for e, data in events if e == "completed")
    assert completed["status"] == "completed"
    assert completed["action_results"][0]["ok"] is True
    assert completed["action_results"][0]["tool"] == "send_email"


def test_approve_stream_reject_path_skips_execution() -> None:
    client, _ = _build(_send_plan)
    chat_resp = client.post("/chat", json={"message": "email a@b.com"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]

    resp = _stream_approve(client, thread_id, _headers("alice"), approve=False)
    assert resp.status_code == 200
    events = _parse_sse(resp.text)
    completed = next(data for e, data in events if e == "completed")
    assert completed["action_results"] == []


def test_approve_stream_denies_non_owner_before_awaiting_check() -> None:
    # A completed (not-awaiting) thread + a non-owner caller must still 403, not 409 — proves
    # ownership is checked BEFORE the state check, so a non-owner can't distinguish thread state by
    # which error code comes back (mirrors the sync /approve's documented anti-enumeration ordering).
    client, _ = _build(_search_plan)  # read-only -> completes immediately, never awaits approval
    chat_resp = client.post("/chat", json={"message": "find"}, headers=_headers("alice"))
    assert chat_resp.json()["status"] == "completed"
    thread_id = chat_resp.json()["thread_id"]

    resp = _stream_approve(client, thread_id, _headers("mallory"), approve=True)
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/json")


def test_approve_stream_404_for_unknown_thread() -> None:
    client, _ = _build(_search_plan)
    resp = _stream_approve(client, "thr_does_not_exist", _headers("alice"), approve=True)
    assert resp.status_code == 404


def test_approve_stream_409_for_owner_on_non_awaiting_thread() -> None:
    client, _ = _build(_search_plan)
    chat_resp = client.post("/chat", json={"message": "find"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]

    resp = _stream_approve(client, thread_id, _headers("alice"), approve=True)
    assert resp.status_code == 409


def test_approve_stream_missing_bearer_token_is_401_before_any_event() -> None:
    # Same security spine as /chat/stream: identity is enforced before any event streams.
    client, _ = _build(_send_plan, authenticator=_unverified_authenticator())
    resp = client.post("/approve/stream", json={"thread_id": "thr_x", "approve": True})
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["ok"] is False


def test_approve_stream_rate_limited_is_429_before_any_event() -> None:
    # 429 must fire before the thread is even looked up (a bogus thread id 429s, not 404s).
    client, _ = _build(_send_plan, rate_limiter=_DenyLimiter())
    resp = _stream_approve(client, "thr_x", _headers("alice"), approve=True)
    assert resp.status_code == 429
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers.get("Retry-After") is not None


def test_approve_stream_openapi_documents_text_event_stream() -> None:
    client, _ = _build(_search_plan)
    content = client.get("/openapi.json").json()["paths"]["/approve/stream"]["post"]["responses"][
        "200"
    ]["content"]
    assert "text/event-stream" in content
    assert "application/json" not in content


# --- token events (M4.8d) — dispatch tested via a fake graph, no real LLM call --
class _FakeMessageChunk:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeStreamGraph:
    """Minimal stand-in for LangGraph's compiled graph: just ``.stream()``/``.get_state()``, enough
    for :func:`atlas.interface.sse.run_graph_stream` / :func:`atlas.interface.routes._stream_lifecycle`
    to run against. Emits synthetic ``updates`` + ``messages`` mode chunks so the token-event dispatch
    path is exercised hermetically — no real graph run or LLM call.
    """

    def __init__(self, snapshot: StateSnapshot) -> None:
        self._snapshot = snapshot

    def stream(self, state: Any, config: Any, *, stream_mode: Any) -> Any:
        del state, config, stream_mode
        yield ("updates", {"planner": {}})
        yield ("messages", (_FakeMessageChunk("Hello"), {"langgraph_node": "responder"}))
        yield ("messages", (_FakeMessageChunk(", world"), {"langgraph_node": "responder"}))
        # A planner-node message must never surface as a token event (no leak of tool-call deltas).
        yield ("messages", (_FakeMessageChunk("SHOULD-NOT-LEAK"), {"langgraph_node": "planner"}))
        yield ("updates", {"responder": {}})

    def get_state(self, config: Any) -> StateSnapshot:
        del config
        return self._snapshot


async def test_token_events_surface_responder_text_filtered_by_node() -> None:
    from types import SimpleNamespace
    from typing import cast

    from langchain_core.messages import AIMessage

    from atlas.interface.routes import _stream_lifecycle
    from atlas.orchestration.graph import Atlas

    snapshot = StateSnapshot(
        values={
            "messages": [AIMessage(content="Hello, world")],
            "sources": [],
            "confidence": 0.9,
            "action_results": [],
        },
        next=(),
        config={},
        metadata=None,
        created_at=None,
        parent_config=None,
        tasks=(),
        interrupts=(),
    )
    atlas = cast(Atlas, SimpleNamespace(graph=_FakeStreamGraph(snapshot)))
    thread_id = "thr_fake"

    events = []
    async for event in _stream_lifecycle(atlas, {}, thread_id, _config(thread_id)):
        assert isinstance(event.data, str)
        events.append((event.event, json.loads(event.data)))

    names = [e for e, _ in events]
    assert names[0] == "open"
    assert names[-1] == "done"
    token_texts = [data["content"] for e, data in events if e == "token"]
    assert token_texts == ["Hello", ", world"]  # only the responder's two chunks, in order
    assert "SHOULD-NOT-LEAK" not in token_texts
    completed = next(data for e, data in events if e == "completed")
    assert completed["response"] == "Hello, world"


# --- _chunk_text (pure helper) ---------------------------------------------------
def test_chunk_text_extracts_plain_string_content() -> None:
    from types import SimpleNamespace

    from atlas.interface.routes import _chunk_text

    assert _chunk_text(SimpleNamespace(content="hello")) == "hello"


def test_chunk_text_extracts_text_blocks_from_list_content() -> None:
    from types import SimpleNamespace

    from atlas.interface.routes import _chunk_text

    chunk = SimpleNamespace(
        content=[{"type": "text", "text": "hi "}, {"type": "text", "text": "there"}]
    )
    assert _chunk_text(chunk) == "hi there"


def test_chunk_text_returns_empty_for_missing_or_none_content() -> None:
    from types import SimpleNamespace

    from atlas.interface.routes import _chunk_text

    assert _chunk_text(SimpleNamespace(content=None)) == ""
    assert _chunk_text(SimpleNamespace()) == ""
