"""HTTP endpoints that drive the compiled LangGraph agent.

Handlers are synchronous (`def`) on purpose: ``graph.invoke``/``get_state`` and the psycopg pool are
blocking, so Starlette runs them in its threadpool rather than on the event loop. The graph is built
once and shared via ``app.state`` (see :mod:`atlas.interface.app`); the checkpointer makes per-thread
state durable, so concurrent requests on different ``thread_id``s are isolated.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Sequence
from typing import Annotated, Any, Final

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, status
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command, StateSnapshot
from sse_starlette import EventSourceResponse, ServerSentEvent

from atlas.governance.rbac import Principal
from atlas.interface.rate_limit import RateLimited
from atlas.interface.schemas import AgentResponse, ApproveRequest, ChatRequest
from atlas.interface.security import RequestPrincipal, thread_owner, verify_thread_owner
from atlas.interface.sse import (
    AWAITING_APPROVAL,
    COMPLETED,
    DONE,
    ERROR,
    NODE,
    OPEN,
    run_graph_stream,
    sse_event,
)
from atlas.orchestration.graph import Atlas
from atlas.orchestration.state import initial_state

logger = logging.getLogger("atlas.interface")

router = APIRouter()

# Cap how long a single SSE write may block on a slow/stuck client before the stream is torn down,
# so one unresponsive consumer can't hold the connection (and its worker) open indefinitely.
SSE_SEND_TIMEOUT_SECONDS: Final = 30


def get_atlas(request: Request) -> Atlas:
    """The shared compiled agent, stored on app.state by create_app."""
    atlas: Atlas = request.app.state.atlas
    return atlas


AtlasDep = Annotated[Atlas, Depends(get_atlas)]


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _last_ai_text(messages: Sequence[Any]) -> str | None:
    """The content of the final message (the responder's AI summary)."""
    if not messages:
        return None
    content = getattr(messages[-1], "content", None)
    if content is None:
        return None
    return content if isinstance(content, str) else str(content)


def _dump(items: Sequence[Any]) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") for item in items]


def _response_from_invoke(thread_id: str, result: dict[str, Any]) -> AgentResponse:
    """Shape the dict returned by graph.invoke (which carries ``__interrupt__`` when it pauses)."""
    interrupts = result.get("__interrupt__")
    if interrupts:
        payload = interrupts[0].value
        return AgentResponse(
            status="awaiting_approval",
            thread_id=thread_id,
            pending_actions=list(payload.get("pending_actions", [])),
        )
    return AgentResponse(
        status="completed",
        thread_id=thread_id,
        response=_last_ai_text(result.get("messages") or []),
        sources=_dump(result.get("sources") or []),
        confidence=result.get("confidence"),
        action_results=_dump(result.get("action_results") or []),
    )


def _response_from_snapshot(thread_id: str, snapshot: StateSnapshot) -> AgentResponse:
    """Shape a read-only view of a thread's current checkpointed state."""
    values = snapshot.values
    if _is_awaiting_approval(snapshot):
        gated = [a for a in (values.get("proposed_actions") or []) if a.needs_approval]
        return AgentResponse(
            status="awaiting_approval", thread_id=thread_id, pending_actions=_dump(gated)
        )
    if _is_in_progress(snapshot):
        return AgentResponse(status="in_progress", thread_id=thread_id)
    return AgentResponse(
        status="completed",
        thread_id=thread_id,
        response=_last_ai_text(values.get("messages") or []),
        sources=_dump(values.get("sources") or []),
        confidence=values.get("confidence"),
        action_results=_dump(values.get("action_results") or []),
    )


def _is_awaiting_approval(snapshot: StateSnapshot) -> bool:
    return "approval" in (snapshot.next or ())


def _is_in_progress(snapshot: StateSnapshot) -> bool:
    return bool(snapshot.next) and not _is_awaiting_approval(snapshot)


def _decision_payload(
    body: ApproveRequest, snapshot: StateSnapshot, caller: Principal
) -> list[dict[str, Any]]:
    """Translate the request into explicit per-action decisions with ``decided_by`` set to the real
    approver (so the audit trail names them). Foreign ids are dropped downstream by _parse_decisions.
    """
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


@router.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}


@router.post("/chat", response_model=AgentResponse, dependencies=[RateLimited])
def chat(body: ChatRequest, principal: RequestPrincipal, atlas: AtlasDep) -> AgentResponse:
    thread_id = f"thr_{uuid.uuid4().hex}"
    result = atlas.graph.invoke(
        initial_state(body.message, principal=principal), _config(thread_id)
    )
    return _response_from_invoke(thread_id, result)


async def _chat_event_stream(
    atlas: Atlas, message: str, principal: Principal, thread_id: str
) -> AsyncIterator[ServerSentEvent]:
    """Stream one chat turn's lifecycle as SSE: ``open → node* → (awaiting_approval | completed) → done``.

    Identity, authorization, and rate limiting have already been enforced by the route's dependencies
    before this generator runs, so the body never streams to a rejected caller. Events expose only the
    fields the existing :class:`AgentResponse` helpers shape (RBAC-filtered sources, etc.); ``node``
    events carry the node name only — never action payloads. Any failure once the stream is open is
    logged server-side and surfaced as a single **generic** ``error`` event (no internals leak), mirroring
    the app's unhandled-error posture. ``done`` is emitted on normal completion or a handled error — but
    not on client disconnect (a ``GeneratorExit`` skips it), which is correct.
    """
    config = _config(thread_id)
    send_stream, receive_stream = anyio.create_memory_object_stream(max_buffer_size=16)
    producer_task = asyncio.create_task(
        run_graph_stream(
            atlas.graph, initial_state(message, principal=principal), config, send_stream
        )
    )
    try:
        yield sse_event(OPEN, {"thread_id": thread_id})
        awaiting = False
        async with receive_stream:
            async for chunk in receive_stream:
                if "__interrupt__" in chunk:
                    response = _response_from_invoke(thread_id, chunk)
                    yield sse_event(AWAITING_APPROVAL, response.model_dump(mode="json"))
                    awaiting = True
                    break
                for node_name in chunk:
                    # updates chunks map node-name -> update, but may also carry internal dunder
                    # keys (e.g. __metadata__); only surface real node names as progress events.
                    if not node_name.startswith("__"):
                        yield sse_event(NODE, {"node": node_name})
        await producer_task
        if not awaiting:
            # get_state hits the (blocking) checkpointer — keep it off the event loop.
            snapshot = await anyio.to_thread.run_sync(atlas.graph.get_state, config)
            response = _response_from_snapshot(thread_id, snapshot)
            yield sse_event(COMPLETED, response.model_dump(mode="json"))
    except Exception:
        logger.exception("Error while streaming chat turn")
        yield sse_event(ERROR, {"code": "internal_error", "message": "Internal server error."})
    finally:
        await receive_stream.aclose()
        if not producer_task.done():
            try:
                await producer_task
            except Exception:  # pragma: no cover - best-effort cleanup; nothing to recover here
                logger.debug("producer task failed during stream cleanup", exc_info=True)
    yield sse_event(DONE, {})


@router.post(
    "/chat/stream",
    response_class=EventSourceResponse,
    responses={
        200: {
            "description": (
                "SSE stream of the chat turn lifecycle "
                "(open → node* → awaiting_approval | completed → done)."
            ),
            "content": {
                "text/event-stream": {
                    "itemSchema": {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "event": {"type": "string"},
                            "data": {
                                "type": "string",
                                "contentMediaType": "application/json",
                            },
                        },
                    }
                }
            },
        }
    },
    dependencies=[RateLimited],
)
async def chat_stream(
    body: ChatRequest, principal: RequestPrincipal, atlas: AtlasDep
) -> EventSourceResponse:
    """Streaming sibling of :func:`chat`: same fresh caller-owned thread, delivered as Server-Sent
    Events. ``X-Accel-Buffering: no`` disables proxy buffering so events flush incrementally."""
    thread_id = f"thr_{uuid.uuid4().hex}"
    return EventSourceResponse(
        _chat_event_stream(atlas, body.message, principal, thread_id),
        headers={"X-Accel-Buffering": "no"},
        send_timeout=SSE_SEND_TIMEOUT_SECONDS,
    )


@router.post("/approve", response_model=AgentResponse, dependencies=[RateLimited])
def approve(body: ApproveRequest, principal: RequestPrincipal, atlas: AtlasDep) -> AgentResponse:
    snapshot = atlas.graph.get_state(_config(body.thread_id))
    if not snapshot.values:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread not found.")
    # Authorize BEFORE any state-dependent check so a non-owner can't distinguish thread state
    # (awaiting vs not) by 409-vs-403 — resume-time binding (403 on mismatch).
    verify_thread_owner(thread_owner(snapshot), principal)
    if not _is_awaiting_approval(snapshot):
        raise HTTPException(status.HTTP_409_CONFLICT, "Thread is not awaiting approval.")
    decisions = _decision_payload(body, snapshot, principal)
    result = atlas.graph.invoke(Command(resume=decisions), _config(body.thread_id))
    return _response_from_invoke(body.thread_id, result)


@router.get("/threads/{thread_id}", response_model=AgentResponse)
def get_thread(thread_id: str, principal: RequestPrincipal, atlas: AtlasDep) -> AgentResponse:
    snapshot = atlas.graph.get_state(_config(thread_id))
    if not snapshot.values:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread not found.")
    verify_thread_owner(thread_owner(snapshot), principal)  # owner-only read (403 on mismatch)
    return _response_from_snapshot(thread_id, snapshot)
