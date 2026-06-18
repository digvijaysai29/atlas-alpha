"""Governance: the append-only audit log.

The audit log is atlas's system of record for "who proposed what, who approved it, and what
happened." It is **append-only by construction**: there is no API to mutate or delete an event.
Events are immutable (``frozen=True``). M1 keeps them in memory; M2 swaps in a durable store behind
the same :class:`AuditLog` interface, with hash-chaining for tamper-evidence.
"""

from __future__ import annotations

import abc
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from atlas.actions import ActionResult, ApprovalDecision, ProposedAction


class AuditEventType(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    SKIPPED = "skipped"  # a gated action that was never approved


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEvent(BaseModel):
    """One immutable entry in the audit trail."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=_utc_now)
    event_type: AuditEventType
    action_id: str
    tool: str | None = None
    actor: str = "system"
    detail: dict[str, Any] = Field(default_factory=dict)


class AuditLog(abc.ABC):
    """Append-only audit interface. Implementations must never expose mutation/deletion."""

    @abc.abstractmethod
    def record(self, event: AuditEvent) -> AuditEvent:
        """Persist an event and return it."""
        raise NotImplementedError

    @abc.abstractmethod
    def events(self) -> tuple[AuditEvent, ...]:
        """Return an immutable snapshot of all events in insertion order."""
        raise NotImplementedError

    # --- convenience recorders ---------------------------------------------
    def proposed(self, action: ProposedAction) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=AuditEventType.PROPOSED,
                action_id=action.action_id,
                tool=action.tool,
                detail={"risk_tier": action.risk_tier.value, "args": action.args},
            )
        )

    def decided(self, decision: ApprovalDecision) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=(
                    AuditEventType.APPROVED if decision.approved else AuditEventType.REJECTED
                ),
                action_id=decision.action_id,
                actor=decision.decided_by,
            )
        )

    def executed(self, result: ActionResult) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=AuditEventType.EXECUTED,
                action_id=result.action_id,
                tool=result.tool,
                detail={"ok": result.ok, "error": result.error},
            )
        )

    def skipped(self, action: ProposedAction, reason: str) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=AuditEventType.SKIPPED,
                action_id=action.action_id,
                tool=action.tool,
                detail={"reason": reason},
            )
        )


class InMemoryAuditLog(AuditLog):
    """Append-only in-memory audit log (M1)."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)
