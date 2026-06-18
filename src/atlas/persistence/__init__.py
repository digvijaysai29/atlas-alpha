"""Data layer: durable persistence backends.

M2.1 adds a Postgres-backed, hash-chained audit store behind the :class:`atlas.governance.AuditLog`
interface. The LangGraph Postgres checkpointer is wired in :mod:`atlas.orchestration.graph`.
"""

from atlas.persistence.audit_store import PostgresAuditLog

__all__ = ["PostgresAuditLog"]
