"""Postgres-backed, hash-chained audit store.

Implements :class:`atlas.governance.AuditLog` over a ``psycopg_pool.ConnectionPool``. Security
properties:

- **No SQL injection:** every value is bound via ``psycopg`` ``%s`` placeholders; the only static SQL
  is the table DDL (no user input).
- **No chain forking under concurrency:** each append takes a transaction-scoped Postgres advisory
  lock, so reading the tail and inserting the new link are atomic across processes.
- **Append-only:** there is no update or delete method.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from atlas.governance import AuditEvent, AuditEventType, AuditLog, ChainedAuditRecord

# Fixed application-wide key for the advisory lock that serializes appends (pg_advisory_xact_lock).
_APPEND_LOCK_KEY = 4_714_115

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS atlas_audit_log (
    seq         BIGINT PRIMARY KEY,
    event_id    TEXT        NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    event_type  TEXT        NOT NULL,
    action_id   TEXT        NOT NULL,
    tool        TEXT,
    actor       TEXT        NOT NULL,
    detail      JSONB       NOT NULL,
    prev_hash   TEXT        NOT NULL,
    event_hash  TEXT        NOT NULL
)
"""

_SELECT_TAIL = "SELECT * FROM atlas_audit_log ORDER BY seq DESC LIMIT 1"
_SELECT_ALL = "SELECT * FROM atlas_audit_log ORDER BY seq ASC"
_HAS_EXECUTED = """
SELECT EXISTS (
    SELECT 1 FROM atlas_audit_log
    WHERE event_type = %s AND action_id = %s
      AND COALESCE((detail->>'ok')::boolean, true) = true
) AS exists
"""
_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_atlas_audit_log_event_action
ON atlas_audit_log (event_type, action_id)
"""
_INSERT = """
INSERT INTO atlas_audit_log
    (seq, event_id, ts, event_type, action_id, tool, actor, detail, prev_hash, event_hash)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def _row_to_record(row: dict[str, Any]) -> ChainedAuditRecord:
    """Rebuild a :class:`ChainedAuditRecord` from a DB row (``dict_row`` factory).

    The timestamp is normalized back to UTC so its canonical serialization (and therefore its hash)
    is identical to when it was first recorded, regardless of the DB session's timezone.
    """
    event = AuditEvent(
        event_id=row["event_id"],
        timestamp=row["ts"].astimezone(timezone.utc),
        event_type=AuditEventType(row["event_type"]),
        action_id=row["action_id"],
        tool=row["tool"],
        actor=row["actor"],
        detail=row["detail"],
    )
    return ChainedAuditRecord(
        seq=row["seq"],
        event=event,
        prev_hash=row["prev_hash"],
        event_hash=row["event_hash"],
    )


class PostgresAuditLog(AuditLog):
    """Durable, tamper-evident audit log stored in Postgres."""

    def __init__(self, pool: ConnectionPool, *, setup: bool = True) -> None:
        self._pool = pool
        if setup:
            self.setup()

    def setup(self) -> None:
        """Create the audit table and idempotency index if absent (idempotent, static DDL)."""
        with self._pool.connection() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)

    def _append_event(self, event: AuditEvent) -> ChainedAuditRecord:
        with self._pool.connection() as conn, conn.transaction():
            # Serialize appends so the tail we read can't change before we insert (no chain fork).
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_APPEND_LOCK_KEY,))
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(_SELECT_TAIL)
                tail_row = cur.fetchone()
            tail = _row_to_record(tail_row) if tail_row else None
            record = self.link(tail, event)
            conn.execute(
                _INSERT,
                (
                    record.seq,
                    event.event_id,
                    event.timestamp,
                    event.event_type.value,
                    event.action_id,
                    event.tool,
                    event.actor,
                    Jsonb(event.detail),
                    record.prev_hash,
                    record.event_hash,
                ),
            )
            return record

    def _load(self) -> list[ChainedAuditRecord]:
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_ALL)
            return [_row_to_record(row) for row in cur.fetchall()]

    def has_executed(self, action_id: str) -> bool:
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_HAS_EXECUTED, (AuditEventType.EXECUTED.value, action_id))
            row = cur.fetchone()
            return bool(row and row["exists"])
