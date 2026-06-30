"""Server-Sent Events plumbing for the streaming interface (M4.7).

Two responsibilities, both **transport-only** (nothing here is checkpointed graph state, so — like the
rest of the interface layer — none of it goes in the ``atlas_serde()`` allowlist):

1. :func:`sse_event` — frame a typed event as an :class:`sse_starlette.ServerSentEvent` with a JSON
   ``data`` payload. The managed ``sse-starlette`` transport handles the wire format, keep-alive ping,
   and client-disconnect detection so we don't hand-roll any of it.
2. :func:`graph_updates` — bridge the **blocking, synchronous** ``graph.stream(...)`` onto the async
   event loop. The persistence stack is synchronous (psycopg pool + ``PostgresSaver``), so LangGraph's
   ``astream`` is not a safe drop-in; instead the blocking iterator is drained in a worker thread that
   pushes each chunk through an ``anyio`` memory-object stream (backpressured), keeping the event loop
   free — the same "blocking graph runs off the event loop" rationale as the sync handlers.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from typing import Any, Final

import anyio
from sse_starlette import ServerSentEvent

logger = logging.getLogger("atlas.interface")

# Event names (the SSE ``event:`` field). Clients switch on these.
OPEN: Final = "open"
NODE: Final = "node"
AWAITING_APPROVAL: Final = "awaiting_approval"
COMPLETED: Final = "completed"
ERROR: Final = "error"
DONE: Final = "done"


def sse_event(event: str, data: dict[str, Any]) -> ServerSentEvent:
    """Frame one typed event. ``data`` is serialized as compact, deterministic JSON."""
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True, default=str)
    return ServerSentEvent(data=payload, event=event)


_DONE = object()  # sentinel: the blocking iterator is exhausted


async def graph_updates(
    graph: Any, state: Any, config: Any
) -> AsyncGenerator[dict[str, Any], None]:
    """Yield each ``stream_mode="updates"`` chunk from the blocking graph, off the event loop.

    The synchronous ``graph.stream`` iterator is advanced one ``next()`` at a time inside a worker
    thread (``anyio.to_thread``), so the blocking checkpointer/pool work never runs on the event loop.
    Stepping (never concurrent) keeps it simple — no task group spanning ``yield`` (which would trip
    anyio's "exit cancel scope in a different task" on early break / client disconnect). If the
    consumer stops early the iterator is closed in ``finally``, best-effort.
    """
    # A LangGraph stream is a generator (has .close()); typed Any so mypy sees the close() in finally.
    iterator: Any = await anyio.to_thread.run_sync(
        lambda: iter(graph.stream(state, config, stream_mode="updates"))
    )

    def _next() -> Any:
        try:
            return next(iterator)
        except StopIteration:
            return _DONE

    try:
        while True:
            chunk = await anyio.to_thread.run_sync(_next)
            if chunk is _DONE:
                return
            yield chunk
    finally:
        with anyio.CancelScope(shield=True):
            try:
                await anyio.to_thread.run_sync(iterator.close)
            except Exception:  # pragma: no cover - best-effort cleanup; nothing to recover here
                logger.debug("graph stream close() failed during cleanup", exc_info=True)
