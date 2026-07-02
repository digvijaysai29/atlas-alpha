"""Per-thread resume serialization for /approve and /approve/stream.

Two concurrent resume requests on the same ``thread_id`` can both pass a pre-stream
``get_state`` awaiting-approval check (TOCTOU). A per-thread lock closes that window:
the first caller holds the lock through ``invoke`` (sync) or through
``iter(graph.stream(...))`` (stream); the second sees a non-awaiting thread and gets HTTP 409.
"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import HTTPException, status
from langchain_core.runnables import RunnableConfig
from langgraph.types import StateSnapshot

from atlas.governance.rbac import Principal
from atlas.interface.schemas import ApproveRequest
from atlas.interface.security import thread_owner, verify_thread_owner
from atlas.orchestration.graph import Atlas

_locks_guard = threading.Lock()
_thread_locks: dict[str, threading.Lock] = {}


def resume_lock(thread_id: str) -> threading.Lock:
    """Return the per-thread resume lock, creating it on first use."""
    with _locks_guard:
        lock = _thread_locks.get(thread_id)
        if lock is None:
            lock = threading.Lock()
            _thread_locks[thread_id] = lock
        return lock


def is_awaiting_approval(snapshot: StateSnapshot) -> bool:
    return "approval" in (snapshot.next or ())


def decision_payload(
    body: ApproveRequest, snapshot: StateSnapshot, caller: Principal
) -> list[dict[str, Any]]:
    """Translate the request into explicit per-action decisions with ``decided_by`` set."""
    by = caller.user_id
    if body.approve is not None:
        gated = [a for a in (snapshot.values.get("proposed_actions") or []) if a.needs_approval]
        return [
            {"action_id": a.action_id, "approved": body.approve, "decided_by": by} for a in gated
        ]
    decisions = [
        {"action_id": aid, "approved": True, "decided_by": by} for aid in body.approved_ids
    ]
    decisions += [
        {"action_id": aid, "approved": False, "decided_by": by} for aid in body.rejected_ids
    ]
    return decisions


def _release_if_held(lock: threading.Lock) -> None:
    if lock.locked():
        lock.release()


def gate_resume(
    atlas: Atlas,
    config: RunnableConfig,
    thread_id: str,
    principal: Principal,
    body: ApproveRequest,
) -> tuple[list[dict[str, Any]], threading.Lock]:
    """Blocking-acquire the per-thread lock, run resume pre-checks, return decisions with lock held.

    On 404 / 403 / 409 the lock is released before raising :class:`HTTPException`.
    """
    lock = resume_lock(thread_id)
    lock.acquire()
    try:
        snapshot = atlas.graph.get_state(config)
        if not snapshot.values:
            _release_if_held(lock)
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread not found.")
        verify_thread_owner(thread_owner(snapshot), principal)
        if not is_awaiting_approval(snapshot):
            _release_if_held(lock)
            raise HTTPException(status.HTTP_409_CONFLICT, "Thread is not awaiting approval.")
        return decision_payload(body, snapshot, principal), lock
    except HTTPException:
        raise
    except Exception:
        _release_if_held(lock)
        raise
