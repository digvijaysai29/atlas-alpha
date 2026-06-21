"""Governance: the append-only, hash-chained audit log.

The audit log is atlas's system of record for "who proposed what, who approved it, and what
happened." Two invariants:

1. **Append-only by construction** — there is no API to mutate or delete an event.
2. **Tamper-evident** — every event is hash-chained to its predecessor, so any insertion, edit,
   reorder, or deletion is detectable via :func:`verify_chain`.

The security-critical hashing lives in ONE place (computed over a deterministic canonical
serialization of a *pure* :class:`AuditEvent`). Storage backends (in-memory, Postgres) implement
only ``_append_event``/``_load`` and inherit the chaining for free — so a future upgrade to a Merkle
tree or external anchoring can replace :func:`compute_event_hash`/:func:`verify_chain` without
touching any storage code.
"""

from __future__ import annotations

import abc
import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from atlas.actions import ActionResult, ApprovalDecision, ProposedAction

# Genesis link for the first event in a chain (64 hex zeros = sha256 width).
GENESIS_HASH = "0" * 64


class AuditEventType(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    REPLAY_SKIPPED = "replay_skipped"  # side effect already committed; executor replay skipped
    FAILED = "failed"  # tool execution failed (retryable — not counted as executed)
    SKIPPED = "skipped"  # a gated action that was never approved
    DENIED = "denied"  # blocked by RBAC (the principal lacked the required permission)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEvent(BaseModel):
    """One immutable entry in the audit trail (the pure domain object — carries no hash)."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=_utc_now)
    event_type: AuditEventType
    action_id: str
    tool: str | None = None
    actor: str = "system"
    detail: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Hashing — deterministic canonical serialization is the crux of tamper-evidence.
# ---------------------------------------------------------------------------
def canonical_event_bytes(event: AuditEvent) -> bytes:
    """Return a deterministic, byte-stable representation of an event.

    Determinism is essential: the same logical event must always hash identically, and any change to
    any field must change the bytes. We dump to JSON-native types (``mode="json"`` → ISO-8601 UTC
    timestamps and enum *values*), then serialize with sorted keys and compact separators so
    whitespace/key-order can never vary.
    """
    payload = event.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_event_hash(prev_hash: str, event: AuditEvent) -> str:
    """Hash an event into the chain: ``sha256(prev_hash || canonical(event))``."""
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode("utf-8"))
    hasher.update(canonical_event_bytes(event))
    return hasher.hexdigest()


class ChainedAuditRecord(BaseModel):
    """An :class:`AuditEvent` plus its position and hash links. Immutable."""

    model_config = ConfigDict(frozen=True)

    seq: int
    event: AuditEvent
    prev_hash: str
    event_hash: str


class ChainVerification(BaseModel):
    """Result of verifying a chain. ``ok`` is True only when every link checks out."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    broken_at: int | None = None  # seq of the first bad record, if any
    reason: str | None = None


def verify_chain(records: Sequence[ChainedAuditRecord]) -> ChainVerification:
    """Verify continuity, prev-linkage, and recomputed hashes across the whole chain.

    Detects mutated events, forged hashes, deleted/inserted records, and reordering.
    """
    expected_prev = GENESIS_HASH
    for index, record in enumerate(records):
        if record.seq != index:
            return ChainVerification(
                ok=False, broken_at=record.seq, reason=f"non-contiguous seq at index {index}"
            )
        if record.prev_hash != expected_prev:
            return ChainVerification(
                ok=False, broken_at=record.seq, reason="prev_hash does not match previous link"
            )
        recomputed = compute_event_hash(record.prev_hash, record.event)
        if recomputed != record.event_hash:
            return ChainVerification(
                ok=False, broken_at=record.seq, reason="event_hash does not match event content"
            )
        expected_prev = record.event_hash
    return ChainVerification(ok=True)


# ---------------------------------------------------------------------------
# Audit log interface — chaining lives here; backends implement only storage.
# ---------------------------------------------------------------------------
class AuditLog(abc.ABC):
    """Append-only, hash-chained audit interface.

    Subclasses implement two storage primitives: ``_append_event`` (which must read the tail and
    persist the new link **atomically**, so concurrent writers can't fork the chain) and ``_load``.
    They must never expose mutation or deletion.
    """

    @staticmethod
    def link(tail: ChainedAuditRecord | None, event: AuditEvent) -> ChainedAuditRecord:
        """Compute the next chained record from the current tail. Hashing lives here, only here."""
        seq = 0 if tail is None else tail.seq + 1
        prev_hash = GENESIS_HASH if tail is None else tail.event_hash
        return ChainedAuditRecord(
            seq=seq,
            event=event,
            prev_hash=prev_hash,
            event_hash=compute_event_hash(prev_hash, event),
        )

    @abc.abstractmethod
    def _append_event(self, event: AuditEvent) -> ChainedAuditRecord:
        """Atomically read the tail, :meth:`link` the event onto it, persist, and return the record."""
        raise NotImplementedError

    @abc.abstractmethod
    def _load(self) -> list[ChainedAuditRecord]:
        """Load all records in insertion order."""
        raise NotImplementedError

    def record(self, event: AuditEvent) -> AuditEvent:
        """Chain and persist an event, then return it."""
        self._append_event(event)
        return event

    def records(self) -> tuple[ChainedAuditRecord, ...]:
        """Immutable snapshot of the full chain."""
        return tuple(self._load())

    def events(self) -> tuple[AuditEvent, ...]:
        """Immutable snapshot of just the events, in order."""
        return tuple(record.event for record in self._load())

    def has_executed(self, action_id: str) -> bool:
        """True when a successful ``EXECUTED`` event exists for ``action_id`` (idempotency check)."""
        return any(
            _counts_as_executed(event) and event.action_id == action_id for event in self.events()
        )

    def verify(self) -> ChainVerification:
        """Verify the persisted chain is intact (tamper-evidence check)."""
        return verify_chain(self._load())

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
        if not result.ok:
            raise ValueError("executed() is success-only; use failed()")
        return self.record(
            AuditEvent(
                event_type=AuditEventType.EXECUTED,
                action_id=result.action_id,
                tool=result.tool,
                detail={"ok": result.ok, "error": result.error},
            )
        )

    def failed(self, result: ActionResult) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=AuditEventType.FAILED,
                action_id=result.action_id,
                tool=result.tool,
                detail={"ok": result.ok, "error": result.error},
            )
        )

    def replay_skipped(self, action: ProposedAction, *, reason: str) -> AuditEvent:
        return self.record(
            AuditEvent(
                event_type=AuditEventType.REPLAY_SKIPPED,
                action_id=action.action_id,
                tool=action.tool,
                detail={"reason": reason},
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

    def denied(self, action: ProposedAction, principal_id: str, reason: str) -> AuditEvent:
        """Record an RBAC denial — the principal lacked the permission a tool required."""
        return self.record(
            AuditEvent(
                event_type=AuditEventType.DENIED,
                action_id=action.action_id,
                tool=action.tool,
                actor=principal_id,
                detail={"reason": reason},
            )
        )


def _counts_as_executed(event: AuditEvent) -> bool:
    """Success-only idempotency marker — ``FAILED`` and legacy ``EXECUTED`` with ``ok=False`` do not count."""
    if event.event_type is not AuditEventType.EXECUTED:
        return False
    return event.detail.get("ok", True) is True


class InMemoryAuditLog(AuditLog):
    """Append-only, hash-chained in-memory audit log (dev/test default)."""

    def __init__(self) -> None:
        self._records: list[ChainedAuditRecord] = []

    def _append_event(self, event: AuditEvent) -> ChainedAuditRecord:
        tail = self._records[-1] if self._records else None
        record = self.link(tail, event)
        self._records.append(record)
        return record

    def _load(self) -> list[ChainedAuditRecord]:
        return list(self._records)
