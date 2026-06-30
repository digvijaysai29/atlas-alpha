"""Server-Sent Events plumbing for the streaming interface (M4.7).

Two responsibilities, both **transport-only** (nothing here is checkpointed graph state, so — like the
rest of the interface layer — none of it goes in the ``atlas_serde()`` allowlist):

1. :func:`sse_event` — frame a typed event as an :class:`sse_starlette.ServerSentEvent` with a JSON
   ``data`` payload. The managed ``sse-starlette`` transport handles the wire format, keep-alive ping,
   and client-disconnect detection so we don't hand-roll any of it.
2. :func:`run_graph_stream` — bridge the **blocking, synchronous** ``graph.stream(...)`` onto the async
   event loop as a background producer. The persistence stack is synchronous (psycopg pool +
   ``PostgresSaver``), so LangGraph's ``astream`` is not a safe drop-in; instead the blocking iterator
   is drained in a worker thread that pushes each chunk through an ``anyio`` memory-object send stream.
   If the consumer disconnects (``BrokenResourceError``), the producer keeps draining silently so the
   graph reaches a terminal checkpoint before ``iterator.close()`` runs in ``finally``.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Final

import anyio
from anyio.streams.memory import MemoryObjectSendStream
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


async def run_graph_stream(
    graph: Any,
    state: Any,
    config: Any,
    send_stream: MemoryObjectSendStream[dict[str, Any]],
) -> None:
    """Run ``graph.stream(..., stream_mode="updates")`` to completion, pushing chunks to *send_stream*.

    The synchronous iterator is advanced one ``next()`` at a time inside a worker thread. If the
    consumer is gone (``anyio.BrokenResourceError`` on send), the producer continues draining the
    iterator silently so the graph reaches a terminal checkpoint. ``iterator.close()`` runs only in
    ``finally`` after the iterator is exhausted.
    """
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
            try:
                await send_stream.send(chunk)
            except anyio.BrokenResourceError:
                while True:
                    chunk = await anyio.to_thread.run_sync(_next)
                    if chunk is _DONE:
                        return
    finally:
        await send_stream.aclose()
        with anyio.CancelScope(shield=True):
            try:
                await anyio.to_thread.run_sync(iterator.close)
            except Exception:  # pragma: no cover - best-effort cleanup; nothing to recover here
                logger.debug("graph stream close() failed during cleanup", exc_info=True)
