"""Data layer: durable persistence backends.

M2.1 adds a Postgres-backed, hash-chained audit store behind the :class:`atlas.governance.AuditLog`
interface; M3.1 adds a Postgres-backed, RBAC-scoped :class:`atlas.knowledge.KnowledgeGraph`. The
LangGraph Postgres checkpointer is wired in :mod:`atlas.orchestration.graph`.
"""

from atlas.persistence.audit_store import PostgresAuditLog
from atlas.persistence.knowledge_store import PostgresKnowledgeGraph

__all__ = ["PostgresAuditLog", "PostgresKnowledgeGraph"]
