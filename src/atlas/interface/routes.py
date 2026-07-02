"""HTTP endpoints that drive the compiled LangGraph agent.

Handlers are synchronous (`def`) on purpose: ``graph.invoke``/``get_state`` and the psycopg pool are
blocking, so Starlette runs them in its threadpool rather than on the event loop. The graph is built
once and shared via ``app.state`` (see :mod:`atlas.interface.app`); the checkpointer makes per-thread
state durable, so concurrent requests on different ``thread_id``s are isolated.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections.abc import AsyncIterator, Sequence
from typing import Annotated, Any, Final

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, status
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command, StateSnapshot
from sse_starlette import EventSourceResponse, ServerSentEvent

from atlas.interface.rate_limit import RateLimited
from atlas.interface.resume_lock import gate_resume, is_awaiting_approval
from atlas.interface.schemas import AgentResponse, ApproveRequest, ChatRequest
from atlas.interface.security import RequestPrincipal, thread_owner, verify_thread_owner
from atlas.interface.sse import (
    AWAITING_APPROVAL,
    COMPLETED,
    DONE,
    ERROR,
    NODE,
    OPEN,
    TOKEN,
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
    return is_awaiting_approval(snapshot)


def _is_in_progress(snapshot: StateSnapshot) -> bool:
    return bool(snapshot.next) and not _is_awaiting_approval(snapshot)


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


def _chunk_text(message_chunk: Any) -> str:
    """Extract plain text from a streamed LLM message chunk.

    Defensive: a chunk's ``content`` may be a plain string or (depending on the provider's streaming
    format) a list of content blocks; non-text blocks (e.g. partial tool-call deltas) are skipped.
    """
    content = getattr(message_chunk, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            block if isinstance(block, str) else block.get("text", "")
            for block in content
            if isinstance(block, str) or isinstance(block, dict)
        ]
        return "".join(p for p in parts if isinstance(p, str))
    return ""


async def _stream_lifecycle(
    atlas: Atlas,
    resumable: Any,
    thread_id: str,
    config: RunnableConfig,
    *,
    resume_lock: threading.Lock | None = None,
) -> AsyncIterator[ServerSentEvent]:
    """Stream one graph run's lifecycle as SSE: ``open → node*/token* → (awaiting_approval |
    completed) → done``. Shared by :func:`chat_stream` (a fresh initial state) and
    :func:`approve_stream` (a ``Command(resume=...)``) — the only difference between the two routes
    is what ``resumable`` is and the authorization check the caller performs first.

    Identity, authorization, and rate limiting have already been enforced by the route's dependencies
    (and, for resume, ``verify_thread_owner``) before this generator runs, so the body never streams
    to a rejected caller. Events expose only the fields the existing :class:`AgentResponse` helpers
    shape (RBAC-filtered sources, etc.); ``node`` events carry the node name only. ``token`` events
    (M4.8d) surface the responder's narrated text as it streams — filtered to the ``responder`` node
    only, so planner tool-call-argument deltas are never forwarded as if they were the answer. Any
    failure once the stream is open is logged server-side and surfaced as a single **generic**
    ``error`` event (no internals leak), mirroring the app's unhandled-error posture. ``done`` is
    emitted on normal completion or a handled error — but not on client disconnect (a
    ``GeneratorExit`` skips it), which is correct.
    """
    send_stream, receive_stream = anyio.create_memory_object_stream(max_buffer_size=16)
    producer_task = asyncio.create_task(
        run_graph_stream(
            atlas.graph,
            resumable,
            config,
            send_stream,
            stream_modes=("updates", "messages"),
            resume_lock=resume_lock,
        )
    )
    try:
        yield sse_event(OPEN, {"thread_id": thread_id})
        awaiting = False
        async with receive_stream:
            async for mode, data in receive_stream:
                if mode == "messages":
                    message_chunk, metadata = data
                    if metadata.get("langgraph_node") != "responder":
                        continue  # never forward planner tool-call deltas as if they were the answer
                    text = _chunk_text(message_chunk)
                    if text:
                        yield sse_event(TOKEN, {"content": text})
                    continue
                if "__interrupt__" in data:
                    response = _response_from_invoke(thread_id, data)
                    yield sse_event(AWAITING_APPROVAL, response.model_dump(mode="json"))
                    awaiting = True
                    break
                for node_name in data:
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
        logger.exception("Error while streaming graph turn")
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
    resumable = initial_state(body.message, principal=principal)
    return EventSourceResponse(
        _stream_lifecycle(atlas, resumable, thread_id, _config(thread_id)),
        headers={"X-Accel-Buffering": "no"},
        send_timeout=SSE_SEND_TIMEOUT_SECONDS,
    )


@router.post("/approve", response_model=AgentResponse, dependencies=[RateLimited])
def approve(body: ApproveRequest, principal: RequestPrincipal, atlas: AtlasDep) -> AgentResponse:
    config = _config(body.thread_id)
    decisions, lock = gate_resume(atlas, config, body.thread_id, principal, body)
    try:
        result = atlas.graph.invoke(Command(resume=decisions), config)
        return _response_from_invoke(body.thread_id, result)
    finally:
        if lock.locked():
            lock.release()


@router.post(
    "/approve/stream",
    response_class=EventSourceResponse,
    responses={
        200: {
            "description": (
                "SSE stream of the resumed turn's lifecycle "
                "(open → node*/token* → awaiting_approval | completed → done)."
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
async def approve_stream(
    body: ApproveRequest, principal: RequestPrincipal, atlas: AtlasDep
) -> EventSourceResponse:
    """Streaming sibling of :func:`approve`: resumes a paused thread, delivered as Server-Sent
    Events. Performs the identical synchronous checks :func:`approve` does — 404 if the thread is
    unknown, then owner verification (403) **before** the awaiting-approval check (409), so a
    non-owner can't distinguish thread state before the body ever streams — this ordering is exactly
    why M4.7 deferred this endpoint. ``get_state`` is a blocking checkpointer call, kept off the event
    loop via a worker thread since this route is ``async``.
    """
    config = _config(body.thread_id)
    decisions, lock = await anyio.to_thread.run_sync(
        gate_resume, atlas, config, body.thread_id, principal, body
    )
    return EventSourceResponse(
        _stream_lifecycle(
            atlas, Command(resume=decisions), body.thread_id, config, resume_lock=lock
        ),
        headers={"X-Accel-Buffering": "no"},
        send_timeout=SSE_SEND_TIMEOUT_SECONDS,
    )


@router.get("/threads/{thread_id}", response_model=AgentResponse)
def get_thread(thread_id: str, principal: RequestPrincipal, atlas: AtlasDep) -> AgentResponse:
    snapshot = atlas.graph.get_state(_config(thread_id))
    if not snapshot.values:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread not found.")
    verify_thread_owner(thread_owner(snapshot), principal)  # owner-only read (403 on mismatch)
    return _response_from_snapshot(thread_id, snapshot)
