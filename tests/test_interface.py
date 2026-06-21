"""HTTP interface tests (offline, hermetic via FastAPI TestClient).

Each app is built with an injected test ``Atlas`` (InMemorySaver + a scripted plan) so no API key,
network, or Postgres is needed. The headline assertions are the **resume-time principal/thread
binding** (caller B cannot approve or read Alice's thread) and that RBAC + anti-replay still hold
through the HTTP layer.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.interface import create_app
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry

from fastapi.testclient import TestClient


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _search_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def _build(plan_fn: PlanFn, settings: Settings | None = None) -> tuple[TestClient, Atlas]:
    atlas = build_graph(
        plan_fn=plan_fn,
        registry=offline_registry(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    app = create_app(atlas=atlas, settings=settings or Settings(ANTHROPIC_API_KEY=None))
    return TestClient(app), atlas


def _headers(user: str, roles: str = "member", org: str | None = None) -> dict[str, str]:
    h = {"X-Atlas-User-Id": user, "X-Atlas-Roles": roles}
    if org is not None:
        h["X-Atlas-Org"] = org
    return h


# --- basics ------------------------------------------------------------------
def test_healthz() -> None:
    client, _ = _build(_search_plan)
    assert client.get("/healthz").json() == {"ok": True}


def test_chat_read_only_auto_completes_with_grounding() -> None:
    client, _ = _build(_search_plan)
    body = client.post("/chat", json={"message": "find things"}, headers=_headers("alice")).json()
    assert body["status"] == "completed"
    assert body["confidence"] is not None
    assert body["thread_id"].startswith("thr_")


def test_chat_send_awaits_approval() -> None:
    client, _ = _build(_send_plan)
    body = client.post("/chat", json={"message": "email a@b.com"}, headers=_headers("alice")).json()
    assert body["status"] == "awaiting_approval"
    assert body["thread_id"]
    assert body["pending_actions"][0]["tool"] == "send_email"


# --- approval flow -----------------------------------------------------------
def test_approve_executes_the_action() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    out = client.post(
        "/approve", json={"thread_id": tid, "approve": True}, headers=_headers("alice")
    ).json()
    assert out["status"] == "completed"
    assert out["action_results"][0]["ok"] is True
    assert out["action_results"][0]["tool"] == "send_email"


def test_reject_skips_the_action() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    out = client.post(
        "/approve", json={"thread_id": tid, "approve": False}, headers=_headers("alice")
    ).json()
    assert out["status"] == "completed"
    assert out["action_results"] == []


def test_approve_attributes_the_decision_to_the_caller() -> None:
    client, atlas = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    client.post("/approve", json={"thread_id": tid, "approve": True}, headers=_headers("alice"))
    approved = [e for e in atlas.audit.events() if e.event_type.value == "approved"]
    assert approved and all(e.actor == "alice" for e in approved)


# --- resume-time principal/thread binding (the security deliverable) ----------
def test_caller_cannot_approve_another_users_thread() -> None:
    client, atlas = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    resp = client.post(
        "/approve", json={"thread_id": tid, "approve": True}, headers=_headers("bob")
    )
    assert resp.status_code == 403
    assert resp.json()["ok"] is False
    # And nothing executed on Alice's behalf.
    assert not [e for e in atlas.audit.events() if e.event_type.value == "executed"]


def test_anonymous_caller_cannot_read_a_thread() -> None:
    # Anonymous = no verified identity, so it never own-binds (even to an anonymous-created thread).
    client, _ = _build(_search_plan)
    tid = client.post("/chat", json={"message": "find"}).json()["thread_id"]  # no identity headers
    assert client.get(f"/threads/{tid}").status_code == 403


def test_approve_authorizes_before_revealing_thread_state() -> None:
    # A non-owner must get 403 even for a COMPLETED (not-awaiting) thread — never a 409 — so thread
    # state can't be enumerated via the status code.
    client, _ = _build(_search_plan)  # auto-completes (never pauses)
    tid = client.post("/chat", json={"message": "find"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    resp = client.post(
        "/approve", json={"thread_id": tid, "approve": True}, headers=_headers("bob")
    )
    assert resp.status_code == 403  # not 409


def test_caller_cannot_read_another_users_thread() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    assert client.get(f"/threads/{tid}", headers=_headers("bob")).status_code == 403


def test_owner_can_read_their_thread() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    body = client.get(f"/threads/{tid}", headers=_headers("alice")).json()
    assert body["status"] == "awaiting_approval"
    assert body["pending_actions"][0]["tool"] == "send_email"


# --- error envelopes ---------------------------------------------------------
def test_approve_unknown_thread_is_404() -> None:
    client, _ = _build(_send_plan)
    resp = client.post(
        "/approve", json={"thread_id": "nope", "approve": True}, headers=_headers("a")
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_approve_thread_not_awaiting_is_409() -> None:
    client, _ = _build(_search_plan)  # auto-completes, never pauses
    tid = client.post("/chat", json={"message": "find"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    resp = client.post(
        "/approve", json={"thread_id": tid, "approve": True}, headers=_headers("alice")
    )
    assert resp.status_code == 409


def test_validation_error_uses_envelope() -> None:
    client, _ = _build(_search_plan)
    resp = client.post("/chat", json={}, headers=_headers("alice"))
    assert resp.status_code == 422
    assert resp.json()["ok"] is False
    assert resp.json()["error"]["code"] == "validation_error"


def test_granular_conflicting_action_id_returns_422() -> None:
    client, atlas = _build(_send_plan)
    chat = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()
    action_id = chat["pending_actions"][0]["action_id"]
    resp = client.post(
        "/approve",
        json={
            "thread_id": chat["thread_id"],
            "approved_ids": [action_id],
            "rejected_ids": [action_id],
        },
        headers=_headers("alice"),
    )
    assert resp.status_code == 422
    assert resp.json()["ok"] is False
    assert not [e for e in atlas.audit.events() if e.event_type.value == "executed"]


def test_mixed_bulk_and_granular_returns_422() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    resp = client.post(
        "/approve",
        json={"thread_id": tid, "approve": True, "rejected_ids": ["act_bogus"]},
        headers=_headers("alice"),
    )
    assert resp.status_code == 422
    assert resp.json()["ok"] is False


def test_spoofed_anonymous_user_id_cannot_access_anonymous_thread() -> None:
    client, _ = _build(_search_plan)
    tid = client.post("/chat", json={"message": "find"}).json()["thread_id"]
    assert client.get(f"/threads/{tid}", headers=_headers("anonymous")).status_code == 403


def test_spoofed_anonymous_user_id_cannot_elevate_rbac() -> None:
    client, _ = _build(_send_plan)
    body = client.post("/chat", json={"message": "email"}, headers=_headers("anonymous")).json()
    assert body["status"] == "completed"
    assert body["pending_actions"] == []
    assert body["action_results"] == []


# --- RBAC + anti-replay still hold through HTTP -------------------------------
def test_anonymous_caller_is_denied_before_approval() -> None:
    client, _ = _build(_send_plan)
    # No identity headers => anonymous => lacks tool:send => denied at planning, never pauses.
    body = client.post("/chat", json={"message": "email"}).json()
    assert body["status"] == "completed"
    assert body["pending_actions"] == []
    assert body["action_results"] == []


def test_foreign_action_id_is_ignored_anti_replay() -> None:
    client, _ = _build(_send_plan)
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    out = client.post(
        "/approve",
        json={"thread_id": tid, "approved_ids": ["act_bogus"]},
        headers=_headers("alice"),
    ).json()
    assert out["status"] == "completed"
    assert out["action_results"] == []  # the real pending action was neither approved nor executed


# --- configurable header names -----------------------------------------------
def test_custom_identity_header_name() -> None:
    settings = Settings(ATLAS_API_USER_HEADER="X-Custom-User", ANTHROPIC_API_KEY=None)
    client, _ = _build(_send_plan, settings=settings)
    # Identity supplied via the custom header is recognized (member => may send => pauses).
    resp = client.post(
        "/chat",
        json={"message": "email"},
        headers={"X-Custom-User": "alice", "X-Atlas-Roles": "member"},
    ).json()
    assert resp["status"] == "awaiting_approval"
    # The default header name is now ignored => anonymous => denied before approval.
    resp2 = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()
    assert resp2["status"] == "completed"
    assert resp2["pending_actions"] == []
