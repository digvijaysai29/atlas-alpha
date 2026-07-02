"""Server-Sent Events plumbing for the streaming interface (M4.7; ``token`` events added in M4.8d).

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

   ``stream_modes`` defaults to just ``"updates"`` (M4.7's lifecycle events, unchanged shape: bare
   per-node update dicts). The interface routes pass ``("updates", "messages")`` so a node's LLM calls
   (when one is configured — the M4.8d responder) also surface as ``token`` events. LangGraph's v1
   stream dispatches on ``isinstance(stream_mode, list)`` — passing a *list* always yields
   ``(mode, data)`` 2-tuples, even for a single mode — so :func:`run_graph_stream` passes a bare
   string when there is exactly one mode (preserving M4.7's exact shape) and a list only when there
   are several; the *consumer* (not this module) is responsible for branching on ``mode`` in that case.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any, Final

import anyio
from anyio.streams.memory import MemoryObjectSendStream
from sse_starlette import ServerSentEvent

logger = logging.getLogger("atlas.interface")

# Event names (the SSE ``event:`` field). Clients switch on these.
OPEN: Final = "open"
NODE: Final = "node"
TOKEN: Final = "token"
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
    send_stream: MemoryObjectSendStream[Any],
    *,
    stream_modes: Sequence[str] = ("updates",),
) -> None:
    """Run ``graph.stream(...)`` to completion, pushing chunks to *send_stream*.

    The synchronous iterator is advanced one ``next()`` at a time inside a worker thread. If the
    consumer is gone (``anyio.BrokenResourceError`` on send), the producer continues draining the
    iterator silently so the graph reaches a terminal checkpoint. ``iterator.close()`` runs only in
    ``finally`` after the iterator is exhausted.
    """
    modes: str | list[str] = stream_modes[0] if len(stream_modes) == 1 else list(stream_modes)
    iterator: Any = await anyio.to_thread.run_sync(
        lambda: iter(graph.stream(state, config, stream_mode=modes))
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
