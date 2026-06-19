"""Confidence scoring + structured source attribution — the transparency layer.

atlas answers carry **where they came from** (:class:`Source`) and **how sure it is**
(:func:`score_confidence`). Sources are derived only from data that already passed upstream gates:
tool outputs from executed (policy- and RBAC-cleared) actions, and knowledge entities from the
already-RBAC-filtered ``kg_context`` — so no unreadable entity is ever cited.

Confidence is a documented **heuristic** for now; real calibration against expected outcomes arrives
with the M2.3 LangSmith evaluation gate.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from atlas.actions import ActionResult

if TYPE_CHECKING:  # annotations only — avoids a runtime governance -> knowledge import edge
    from atlas.knowledge.interfaces import Entity

# --- Confidence heuristics (pending real calibration in M2.3) ----------------
# Used only when no actions ran, to reflect whether the answer was grounded in retrieved knowledge.
GROUNDED_ANSWER = 0.8  # grounded in retrieved (RBAC-scoped) knowledge
UNGROUNDED_ANSWER = 0.5  # no grounding — deliberately surfaced low, not hidden


class Source(BaseModel):
    """Structured provenance for part of an answer. Immutable."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["tool", "knowledge"]
    ref: str  # tool name (kind="tool") or entity id (kind="knowledge")
    label: str = ""  # human-readable: the tool's source string, or the entity name


def collect_sources(
    action_results: Sequence[ActionResult], kg_context: Sequence[Entity]
) -> list[Source]:
    """Gather de-duplicated, structured provenance from tool outputs + retrieved knowledge.

    De-duplicates by ``(kind, ref)`` while preserving first-seen order.
    """
    sources: list[Source] = []
    seen: set[tuple[str, str]] = set()

    def _add(source: Source) -> None:
        key = (source.kind, source.ref)
        if key not in seen:
            seen.add(key)
            sources.append(source)

    for result in action_results:
        # Only some tools (today: READ tools) emit a "source" in their dict output — be defensive.
        if result.ok and isinstance(result.output, dict):
            label = result.output.get("source")
            if label:
                _add(Source(kind="tool", ref=result.tool, label=str(label)))

    for entity in kg_context:
        _add(Source(kind="knowledge", ref=entity.id, label=entity.name))

    return sources


def score_confidence(action_results: Sequence[ActionResult], kg_context: Sequence[Entity]) -> float:
    """Heuristic confidence in ``[0.0, 1.0]``.

    - Actions executed → the fraction that succeeded (execution success dominates).
    - No actions → reflects whether the answer was grounded in retrieved knowledge.
    """
    if action_results:
        ok = sum(1 for result in action_results if result.ok)
        return round(ok / len(action_results), 2)
    return GROUNDED_ANSWER if kg_context else UNGROUNDED_ANSWER
