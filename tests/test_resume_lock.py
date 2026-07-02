"""Resume lock reclamation, deadlock, and owner-safety regression tests."""

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
from atlas.interface.resume_lock import _entries, acquire_resume_lock, gate_resume
from atlas.interface.routes import _config
from atlas.interface.schemas import ApproveRequest
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _build() -> tuple[TestClient, Atlas]:
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
    _entries.clear()


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
    decisions, lease = gate_resume(atlas, config, thread_id, alice, body)
    try:
        atlas.graph.invoke(Command(resume=decisions), config)
    finally:
        lease.release()


def test_forbidden_approve_does_not_block_later_owner_approval() -> None:
    """End-to-end regression: a non-owner 403 must not leave the thread's resume wedged."""
    _clear_lock_cache()
    client, _ = _build()
    chat_resp = client.post("/chat", json={"message": "email"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]

    denied = client.post(
        "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("mallory")
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("alice")
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "completed"


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
    assert thread_id not in _entries


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

    assert len(_entries) == 0


def test_successful_approve_discards_lock() -> None:
    _clear_lock_cache()
    client, _ = _build()
    chat_resp = client.post("/chat", json={"message": "email"}, headers=_headers("alice"))
    thread_id = chat_resp.json()["thread_id"]

    resp = client.post(
        "/approve", json={"thread_id": thread_id, "approve": True}, headers=_headers("alice")
    )
    assert resp.status_code == 200
    assert thread_id not in _entries


def test_lease_release_is_idempotent_and_owner_safe() -> None:
    """A stale lease's second release must never unlock a lock another caller now holds.

    This is the regression for the raw ``if lock.locked(): lock.release()`` pattern, which released
    whoever currently held the lock when a cleanup path ran twice.
    """
    _clear_lock_cache()
    thread_id = "thr_owner_safety"

    first = acquire_resume_lock(thread_id)
    first.release()

    second = acquire_resume_lock(thread_id)
    # Stale duplicate releases from the first caller's other cleanup paths: must be no-ops.
    first.release()
    first.release()

    # The second caller still exclusively holds the resume lock for this thread.
    assert _entries[thread_id].lock.locked() is True
    assert _entries[thread_id].lock.acquire(blocking=False) is False

    second.release()
    assert thread_id not in _entries
