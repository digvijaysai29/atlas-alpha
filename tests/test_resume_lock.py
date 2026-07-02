"""Resume lock reclamation and deadlock regression tests."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.resume_lock import _thread_locks, finish_resume_lock, gate_resume
from atlas.interface.routes import _config
from atlas.interface.schemas import ApproveRequest
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _build() -> tuple[TestClient, object]:
    atlas = build_graph(
        plan_fn=_send_plan,
        registry=offline_registry(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    app = create_app(atlas=atlas, settings=Settings(ANTHROPIC_API_KEY=None))
    return TestClient(app), atlas


def _headers(user: str) -> dict[str, str]:
    return {"X-Atlas-User-Id": user, "X-Atlas-Roles": "member"}


def _clear_lock_cache() -> None:
    _thread_locks.clear()


def test_gate_resume_403_releases_lock() -> None:
    _clear_lock_cache()
    client, atlas = _build()
    chat_resp = client.post("/chat", json={"message": "email"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]
    config = _config(thread_id)
    body = ApproveRequest(thread_id=thread_id, approve=True)
    bob = Principal(user_id="bob", roles=("member",))

    with pytest.raises(HTTPException) as exc_info:
        gate_resume(atlas, config, thread_id, bob, body)
    assert exc_info.value.status_code == 403

    alice = Principal(user_id="alice", roles=("member",))
    decisions, lock = gate_resume(atlas, config, thread_id, alice, body)
    try:
        atlas.graph.invoke(Command(resume=decisions), config)
    finally:
        finish_resume_lock(thread_id, lock)


def test_gate_resume_404_discards_lock() -> None:
    _clear_lock_cache()
    _, atlas = _build()
    thread_id = "thr_does_not_exist"
    config = _config(thread_id)
    body = ApproveRequest(thread_id=thread_id, approve=True)
    principal = Principal(user_id="alice", roles=("member",))

    with pytest.raises(HTTPException) as exc_info:
        gate_resume(atlas, config, thread_id, principal, body)
    assert exc_info.value.status_code == 404
    assert thread_id not in _thread_locks


def test_many_unknown_thread_ids_do_not_grow_lock_cache() -> None:
    _clear_lock_cache()
    _, atlas = _build()
    principal = Principal(user_id="alice", roles=("member",))

    for _ in range(50):
        thread_id = f"thr_{uuid.uuid4().hex}"
        config = _config(thread_id)
        body = ApproveRequest(thread_id=thread_id, approve=True)
        with pytest.raises(HTTPException):
            gate_resume(atlas, config, thread_id, principal, body)

    assert len(_thread_locks) == 0


def test_successful_approve_discards_lock() -> None:
    _clear_lock_cache()
    client, _ = _build()
    chat_resp = client.post("/chat", json={"message": "email"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]

    resp = client.post(
        "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("alice")
    )
    assert resp.status_code == 200
    assert thread_id not in _thread_locks
