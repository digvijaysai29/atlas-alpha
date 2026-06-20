"""Postgres-backed, RBAC-scoped KnowledgeGraph (M3.1).

A durable implementation of :class:`atlas.knowledge.interfaces.KnowledgeGraph` using **Postgres
full-text search** (``tsvector`` + an ILIKE substring fallback) — no vector embeddings. It mirrors
the :class:`atlas.persistence.audit_store.PostgresAuditLog` style and shares the same connection
pool. Security properties:

- **RBAC filter pushed into the query:** the ``WHERE`` clause excludes any entity the principal may
  not read, so unreadable rows are never even fetched. The result is then re-filtered through
  :func:`can_read` in Python (defense-in-depth) so the backend can never accidentally surface an
  entity the in-memory backend would have hidden (backend parity).
- **No SQL injection:** every value — including the query text, the principal's permission set, and
  the per-term ILIKE patterns — is bound via ``psycopg`` placeholders. All SQL is static.
- **No model-driven authorization:** the readable set is derived from the principal's roles via
  :func:`get_effective_permissions`, never from anything the LLM produced.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from atlas.governance.policy import DEFAULT_POLICY, PolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity, KnowledgeGraph, Relation, can_read

_ADMIN_WILDCARD = "*"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS atlas_kg_entities (
    id      TEXT PRIMARY KEY,
    type    TEXT   NOT NULL,
    name    TEXT   NOT NULL,
    content TEXT   NOT NULL DEFAULT '',
    acl     TEXT[] NOT NULL DEFAULT '{}',
    scope   TEXT   NOT NULL DEFAULT 'org'
);
CREATE TABLE IF NOT EXISTS atlas_kg_relations (
    src_id TEXT NOT NULL,
    dst_id TEXT NOT NULL,
    type   TEXT NOT NULL
);
"""

# Full-text GIN index over name + content. The ILIKE fallback below is unindexed today; that is fine
# at this corpus size.
# TODO(perf): add a pg_trgm GIN index to back the ILIKE substring fallback when the corpus grows.
_CREATE_FTS_INDEX = """
CREATE INDEX IF NOT EXISTS atlas_kg_fts
    ON atlas_kg_entities USING GIN (to_tsvector('english', name || ' ' || content))
"""

_UPSERT_ENTITY = """
INSERT INTO atlas_kg_entities (id, type, name, content, acl, scope)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (id) DO UPDATE SET
    type = EXCLUDED.type,
    name = EXCLUDED.name,
    content = EXCLUDED.content,
    acl = EXCLUDED.acl,
    scope = EXCLUDED.scope
"""

_INSERT_RELATION = "INSERT INTO atlas_kg_relations (src_id, dst_id, type) VALUES (%s, %s, %s)"
_SELECT_RELATIONS = "SELECT src_id, dst_id, type FROM atlas_kg_relations ORDER BY src_id, dst_id"

# RBAC: readable iff the principal is an admin wildcard, the acl is NULL/empty (world-readable), or
# the acl array overlaps (``&&``) the principal's effective permission set.
# Relevance: no search terms ⇒ match all; otherwise full-text match OR any-term substring (ILIKE
# ANY) so behavior matches the in-memory keyword-OR stub.
_QUERY = """
SELECT id, type, name, content, acl, scope
FROM atlas_kg_entities
WHERE (
        %(is_admin)s = TRUE
        OR acl IS NULL
        OR cardinality(acl) = 0
        OR acl && %(perms)s::text[]
    )
    AND (
        %(match_all)s = TRUE
        OR to_tsvector('english', name || ' ' || content) @@ plainto_tsquery('english', %(text)s)
        OR name ILIKE ANY(%(patterns)s::text[])
        OR content ILIKE ANY(%(patterns)s::text[])
    )
ORDER BY id
LIMIT %(limit)s
"""


def _like_escape(term: str) -> str:
    """Escape LIKE/ILIKE wildcards so a query term is matched literally (substring), matching the
    in-memory backend's ``term in haystack`` semantics. Order matters: escape the backslash first.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row_to_entity(row: dict[str, Any]) -> Entity:
    """Rebuild an :class:`Entity` from a DB row (``dict_row`` factory)."""
    return Entity(
        id=row["id"],
        type=row["type"],
        name=row["name"],
        content=row["content"],
        acl=tuple(row["acl"] or ()),
        scope=row["scope"],
    )


class PostgresKnowledgeGraph(KnowledgeGraph):
    """Durable, RBAC-scoped knowledge graph stored in Postgres."""

    def __init__(
        self, pool: ConnectionPool, policy: PolicyStore | None = None, *, setup: bool = True
    ) -> None:
        self._pool = pool
        self._policy = policy or DEFAULT_POLICY  # governs the RBAC read filter
        if setup:
            self.setup()

    def setup(self) -> None:
        """Create the KG tables + FTS index if absent (idempotent, static DDL)."""
        with self._pool.connection() as conn:
            conn.execute(_CREATE_TABLES)
            conn.execute(_CREATE_FTS_INDEX)

    def upsert_entity(self, entity: Entity) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                _UPSERT_ENTITY,
                (
                    entity.id,
                    entity.type,
                    entity.name,
                    entity.content,
                    list(entity.acl),
                    entity.scope,
                ),
            )

    def add_relation(self, relation: Relation) -> None:
        with self._pool.connection() as conn:
            conn.execute(_INSERT_RELATION, (relation.src_id, relation.dst_id, relation.type))

    def relations(self) -> Sequence[Relation]:
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_RELATIONS)
            return tuple(
                Relation(src_id=row["src_id"], dst_id=row["dst_id"], type=row["type"])
                for row in cur.fetchall()
            )

    def query(self, principal: Principal | None, text: str, *, limit: int = 5) -> list[Entity]:
        permissions = self._policy.effective_permissions(principal)
        is_admin = _ADMIN_WILDCARD in permissions
        terms = [term for term in text.lower().split() if term]
        params = {
            "is_admin": is_admin,
            "perms": list(permissions),
            "match_all": not terms,
            "text": text,
            "patterns": [f"%{_like_escape(term)}%" for term in terms],
            "limit": limit,
        }
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_QUERY, params)
            entities = [_row_to_entity(row) for row in cur.fetchall()]
        # Defense-in-depth: never trust the query alone — re-apply can_read before returning.
        return [entity for entity in entities if can_read(principal, entity, self._policy)]
