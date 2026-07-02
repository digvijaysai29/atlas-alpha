"""Per-thread resume serialization for /approve and /approve/stream.

Two concurrent resume requests on the same ``thread_id`` can both pass a pre-stream
``get_state`` awaiting-approval check (TOCTOU). A per-thread lock closes that window:
the first caller holds the lock through ``invoke`` (sync) or through
``iter(graph.stream(...))`` (stream); the second sees a non-awaiting thread and gets HTTP 409.

Callers hold the lock via a :class:`ResumeLease` whose ``release()`` is **idempotent and
owner-safe**: releasing twice (or after another request has re-acquired the underlying lock) can
never unlock someone else's resume — unlike a raw ``Lock.release()`` guarded by ``lock.locked()``,
which releases whoever holds it. Entries are refcounted, so the map cannot grow without bound from
404 probes, yet an entry is never dropped while another caller is still blocked on it (which would
mint a second lock for the same thread and reopen the race).

Scope: this serializes resumes **within one Python process** — its job is the deterministic
pre-stream 409, not side-effect safety. Duplicate side effects from a cross-worker double resume
are independently prevented by the durable audit-ledger idempotency in
:class:`atlas.execution.GuardedExecutor` (an already-executed ``action_id`` replays as a no-op),
which is exactly why real senders require ``DATABASE_URL``. Multi-worker deployments that also
want the deterministic 409 need sticky routing for approvals or a future cross-process advisory
lock (see RUNBOOK).
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


class _LockEntry:
    __slots__ = ("lock", "refs")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refs = 0


_entries_guard = threading.Lock()
_entries: dict[str, _LockEntry] = {}


class ResumeLease:
    """One caller's exclusive hold on a thread's resume lock.

    Created only by :func:`acquire_resume_lock` (i.e. with the lock already held). ``release()``
    may be called from any of the multiple cleanup paths a streaming response has (pre-check error,
    producer start, producer ``finally``, response background task) — the first call releases, the
    rest are no-ops.
    """

    def __init__(self, thread_id: str, entry: _LockEntry) -> None:
        self._thread_id = thread_id
        self._entry = entry
        self._released = False
        self._release_guard = threading.Lock()

    def release(self) -> None:
        with self._release_guard:
            if self._released:
                return
            self._released = True
        self._entry.lock.release()
        with _entries_guard:
            self._entry.refs -= 1
            if self._entry.refs == 0 and _entries.get(self._thread_id) is self._entry:
                del _entries[self._thread_id]


def acquire_resume_lock(thread_id: str) -> ResumeLease:
    """Blocking-acquire the per-thread resume lock; the returned lease must eventually be released.

    The refcount is bumped *before* blocking on the lock, so a waiting caller keeps the entry alive
    — the holder's release can never delete an entry someone is still queued on.
    """
    with _entries_guard:
        entry = _entries.get(thread_id)
        if entry is None:
            entry = _LockEntry()
            _entries[thread_id] = entry
        entry.refs += 1
    entry.lock.acquire()
    return ResumeLease(thread_id, entry)


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


def gate_resume(
    atlas: Atlas,
    config: RunnableConfig,
    thread_id: str,
    principal: Principal,
    body: ApproveRequest,
) -> tuple[list[dict[str, Any]], ResumeLease]:
    """Blocking-acquire the per-thread lock, run resume pre-checks, return decisions + held lease.

    Any failure — 404 (unknown thread), 403 (non-owner, raised by ``verify_thread_owner``),
    409 (not awaiting), or an unexpected error — releases the lease before propagating, so a
    rejected caller can never leave the thread's resume permanently blocked.
    """
    lease = acquire_resume_lock(thread_id)
    try:
        snapshot = atlas.graph.get_state(config)
        if not snapshot.values:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread not found.")
        verify_thread_owner(thread_owner(snapshot), principal)
        if not is_awaiting_approval(snapshot):
            raise HTTPException(status.HTTP_409_CONFLICT, "Thread is not awaiting approval.")
        return decision_payload(body, snapshot, principal), lease
    except BaseException:
        lease.release()
        raise
