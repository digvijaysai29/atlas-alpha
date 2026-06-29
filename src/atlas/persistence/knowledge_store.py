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

from psycopg import Connection, errors as pg_errors
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from atlas.governance.policy import DEFAULT_POLICY, PolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.embeddings import EmbeddingProvider
from atlas.knowledge.interfaces import (
    IDENTITY_ACL_PREFIX,
    Entity,
    KnowledgeGraph,
    Relation,
    can_read,
    identity_acl,
)

_ADMIN_WILDCARD = "*"

# Reciprocal Rank Fusion constant (the standard k=60) and how deep we fetch each branch before fusing.
# A larger candidate pool than ``limit`` lets the ``can_read`` re-filter drop rows without starving the
# result, and gives RRF enough overlap to rank well.
_RRF_K = 60
_CANDIDATE_MULTIPLIER = 4
_BACKFILL_BATCH = 50

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

# Dedup edges so re-ingesting the same document is idempotent. ``CREATE TABLE IF NOT EXISTS`` is a
# no-op on already-deployed tables, so this separate ``CREATE UNIQUE INDEX IF NOT EXISTS`` (run in
# ``setup()``) is what guarantees existing deployments also get the constraint. It also serves as the
# ``ON CONFLICT (src_id, dst_id, type)`` arbiter for ``_INSERT_RELATION``.
_CREATE_RELATIONS_UNIQUE_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS atlas_kg_relations_uniq
    ON atlas_kg_relations (src_id, dst_id, type)
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

# Vector-aware upsert (M4.6): identical to ``_UPSERT_ENTITY`` plus the embedding. The vector is bound as
# a pgvector text literal and cast with ``::vector`` — still fully parameterized (no string injection).
_UPSERT_ENTITY_VEC = """
INSERT INTO atlas_kg_entities (id, type, name, content, acl, scope, embedding)
VALUES (%s, %s, %s, %s, %s, %s, %s::vector)
ON CONFLICT (id) DO UPDATE SET
    type = EXCLUDED.type,
    name = EXCLUDED.name,
    content = EXCLUDED.content,
    acl = EXCLUDED.acl,
    scope = EXCLUDED.scope,
    embedding = EXCLUDED.embedding
"""

# Idempotent edge insert: re-adding an identical (src_id, dst_id, type) is a silent no-op. The
# ``ON CONFLICT`` target is the unique index ``atlas_kg_relations_uniq`` created in ``setup()`` (see
# ``_CREATE_RELATIONS_UNIQUE_INDEX``), so re-ingesting the same document never grows the table.
_INSERT_RELATION = (
    "INSERT INTO atlas_kg_relations (src_id, dst_id, type) VALUES (%s, %s, %s) "
    "ON CONFLICT (src_id, dst_id, type) DO NOTHING"
)
_SELECT_RELATIONS = "SELECT src_id, dst_id, type FROM atlas_kg_relations ORDER BY src_id, dst_id"

# RBAC predicate (shared verbatim by the full-text AND the vector branch — see ``_QUERY`` /
# ``_VECTOR_QUERY``). Readable iff the acl is NULL/empty (world-readable), the acl array overlaps
# (``&&``) the principal's exact permission grants (including their identity ACL for PKG), an acl entry
# matches one of the principal's hierarchical ``":*"`` grants on **non-identity** entries only, OR the
# principal is an admin wildcard and the row is not another user's identity-only PKG. Wildcards are
# honored on the granted side only — keeping the SQL filter in parity with ``can_read``. Composing both
# retrieval queries from this one fragment guarantees semantic (vector) search cannot widen read access
# beyond keyword search (no IDOR via embeddings).
# The canonical RBAC predicate. It is inlined **verbatim** into both queries below (kept as static
# literals so the SQL is never built by string formatting). ``test_rbac_predicate_is_shared_by_both
# _query_branches`` asserts this exact text appears in both, so the full-text and vector branches can
# never drift apart — semantic search cannot widen read access (no IDOR via embeddings).
_RBAC_PREDICATE = """(
        acl IS NULL
        OR cardinality(acl) = 0
        OR acl && %(exact)s::text[]
        OR EXISTS (
            SELECT 1 FROM unnest(acl) AS a
            WHERE NOT a LIKE %(identity_prefix)s
              AND a LIKE ANY(%(wildcard_like)s::text[])
        )
        OR (
            %(is_admin)s = TRUE
            AND (
                EXISTS (
                    SELECT 1 FROM unnest(acl) AS a
                    WHERE NOT a LIKE %(identity_prefix)s
                )
                OR acl && %(exact)s::text[]
            )
        )
    )"""

# Full-text branch. Relevance: no search terms ⇒ match all; otherwise full-text match OR any-term
# substring (ILIKE ANY) so behavior matches the in-memory keyword-OR stub.
_QUERY = """
SELECT id, type, name, content, acl, scope
FROM atlas_kg_entities
WHERE (
        acl IS NULL
        OR cardinality(acl) = 0
        OR acl && %(exact)s::text[]
        OR EXISTS (
            SELECT 1 FROM unnest(acl) AS a
            WHERE NOT a LIKE %(identity_prefix)s
              AND a LIKE ANY(%(wildcard_like)s::text[])
        )
        OR (
            %(is_admin)s = TRUE
            AND (
                EXISTS (
                    SELECT 1 FROM unnest(acl) AS a
                    WHERE NOT a LIKE %(identity_prefix)s
                )
                OR acl && %(exact)s::text[]
            )
        )
    )
    AND (
        %(match_all)s = TRUE
        OR to_tsvector('english', name || ' ' || content) @@ plainto_tsquery('english', %(text)s)
        OR name ILIKE ANY(%(patterns)s::text[])
        OR content ILIKE ANY(%(patterns)s::text[])
    )
ORDER BY id
LIMIT %(limit)s
OFFSET %(offset)s
"""

# Vector branch (M4.6). Same RBAC predicate (inlined verbatim); ranks readable rows that have an
# embedding by cosine distance (``<=>``) to the bound query vector (a parameterized ``::vector`` literal).
_VECTOR_QUERY = """
SELECT id, type, name, content, acl, scope
FROM atlas_kg_entities
WHERE (
        acl IS NULL
        OR cardinality(acl) = 0
        OR acl && %(exact)s::text[]
        OR EXISTS (
            SELECT 1 FROM unnest(acl) AS a
            WHERE NOT a LIKE %(identity_prefix)s
              AND a LIKE ANY(%(wildcard_like)s::text[])
        )
        OR (
            %(is_admin)s = TRUE
            AND (
                EXISTS (
                    SELECT 1 FROM unnest(acl) AS a
                    WHERE NOT a LIKE %(identity_prefix)s
                )
                OR acl && %(exact)s::text[]
            )
        )
    )
    AND embedding IS NOT NULL
ORDER BY embedding <=> %(qvec)s::vector
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


def _vector_literal(vector: Sequence[float]) -> str:
    """Render a vector as a pgvector text literal (e.g. ``[0.1,0.2]``) for a bound ``::vector`` param."""
    return "[" + ",".join(repr(float(value)) for value in vector) + "]"


def _embedding_text(entity: Entity) -> str:
    """The text embedded for an entity: its name and content (same shape the FTS index covers)."""
    return f"{entity.name}\n{entity.content}"


def _rrf_fuse(rankings: Sequence[Sequence[str]], *, k: int) -> list[str]:
    """Reciprocal Rank Fusion: merge ranked id lists into one order by summed ``1/(k+rank)`` scores.

    Deterministic: ties break on first appearance (insertion order is stable in ``dict``).
    """
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, entity_id in enumerate(ranking):
            scores[entity_id] = scores.get(entity_id, 0.0) + 1.0 / (k + rank + 1)
    return sorted(scores, key=lambda entity_id: scores[entity_id], reverse=True)


class PostgresKnowledgeGraph(KnowledgeGraph):
    """Durable, RBAC-scoped knowledge graph stored in Postgres."""

    def __init__(
        self,
        pool: ConnectionPool,
        policy: PolicyStore | None = None,
        *,
        embedder: EmbeddingProvider | None = None,
        setup: bool = True,
    ) -> None:
        self._pool = pool
        self._policy = policy or DEFAULT_POLICY  # governs the RBAC read filter
        # When an embedder is injected, entities are embedded on upsert and ``query`` runs hybrid
        # (full-text + vector) retrieval. With no embedder the backend is exactly the M3.1 FTS store.
        self._embedder = embedder
        if setup:
            self.setup()

    def setup(self) -> None:
        """Create the KG tables + FTS index if absent (idempotent, static DDL).

        When an embedder is configured, also enable pgvector, add the ``embedding`` column (sized to the
        embedder's ``dim``), and build an HNSW cosine index. The dim is a validated positive integer
        (never user input), so interpolating it into the DDL is safe.

        If the column already exists at the wrong width, it is dropped and recreated. Rows with
        ``embedding IS NULL`` are backfilled in small batches (embed outside the connection).
        """
        with self._pool.connection() as conn:
            conn.execute(_CREATE_TABLES)
            conn.execute(_CREATE_FTS_INDEX)
            conn.execute(_CREATE_RELATIONS_UNIQUE_INDEX)
            if self._embedder is not None:
                dim = int(self._embedder.dim)
                conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                conn.execute(
                    f"ALTER TABLE atlas_kg_entities ADD COLUMN IF NOT EXISTS embedding vector({dim})"
                )
                existing_dim = self._embedding_column_dim(conn)
                if existing_dim is not None and existing_dim != dim:
                    conn.execute("DROP INDEX IF EXISTS atlas_kg_hnsw")
                    conn.execute("ALTER TABLE atlas_kg_entities DROP COLUMN embedding")
                    conn.execute(
                        f"ALTER TABLE atlas_kg_entities ADD COLUMN embedding vector({dim})"
                    )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS atlas_kg_hnsw "
                    "ON atlas_kg_entities USING hnsw (embedding vector_cosine_ops)"
                )
        if self._embedder is not None:
            self._backfill_null_embeddings()

    @staticmethod
    def _embedding_column_dim(conn: Connection) -> int | None:
        """Return the pgvector dimension of ``atlas_kg_entities.embedding``, or ``None`` if absent."""
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT a.atttypmod AS dim
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname = 'atlas_kg_entities'
                  AND a.attname = 'embedding'
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                """
            )
            row = cur.fetchone()
        if row is None or row["dim"] < 0:
            return None
        return int(row["dim"])

    def _backfill_null_embeddings(self) -> None:
        """Embed and persist any rows left with ``embedding IS NULL`` (batched, no held connection)."""
        if self._embedder is None:
            return
        embedder = self._embedder
        while True:
            with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, name, content
                    FROM atlas_kg_entities
                    WHERE embedding IS NULL
                    LIMIT %s
                    """,
                    (_BACKFILL_BATCH,),
                )
                rows = cur.fetchall()
            if not rows:
                return
            texts = [f"{row['name']}\n{row['content']}" for row in rows]
            vectors = embedder.embed(texts, input_type="document")
            with self._pool.connection() as conn:
                for row, vector in zip(rows, vectors, strict=True):
                    conn.execute(
                        "UPDATE atlas_kg_entities SET embedding = %s::vector WHERE id = %s",
                        (_vector_literal(vector), row["id"]),
                    )

    def upsert_entity(self, entity: Entity) -> None:
        base = (
            entity.id,
            entity.type,
            entity.name,
            entity.content,
            list(entity.acl),
            entity.scope,
        )
        vector: list[float] | None = None
        if self._embedder is not None:
            # Compute embedding before acquiring a pooled connection (Voyage can be slow).
            try:
                vector = self._embedder.embed_one(_embedding_text(entity), input_type="document")
            except Exception:
                vector = None
        with self._pool.connection() as conn:
            if vector is None:
                conn.execute(_UPSERT_ENTITY, base)
            else:
                conn.execute(_UPSERT_ENTITY_VEC, (*base, _vector_literal(vector)))

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

    def bind_policy(self, policy: PolicyStore) -> None:
        self._policy = policy

    def query(self, principal: Principal | None, text: str, *, limit: int = 5) -> list[Entity]:
        permissions = self._policy.effective_permissions(principal)
        is_admin = _ADMIN_WILDCARD in permissions
        # Exact grants drive the array-overlap (``&&``) clause; hierarchical ``a:b:*`` grants become
        # LIKE prefix patterns ("a:b:%"), with the prefix ``_like_escape``-d so a permission string
        # can never inject LIKE metacharacters. ``LIKE ANY('{}')`` is harmless (false) when empty.
        exact = [p for p in permissions if p != _ADMIN_WILDCARD and not p.endswith(":*")]
        # Identity ACL (PKG isolation): grant the principal read on entities tagged
        # ``kg:read:user:<their id>`` via the same static ``acl && %(exact)s`` overlap clause.
        # Wildcard grants are prevented from matching identity ACL rows in SQL (see ``identity_prefix``),
        # and ``can_read`` remains the authority (defense-in-depth).
        if principal is not None:
            exact = [*exact, identity_acl(principal.user_id)]
        wildcard_like = [f"{_like_escape(p[:-1])}%" for p in permissions if p.endswith(":*")]
        terms = [term for term in text.lower().split() if term]
        identity_prefix = f"{IDENTITY_ACL_PREFIX}%"
        base_params = {
            "is_admin": is_admin,
            "exact": exact,
            "wildcard_like": wildcard_like,
            "identity_prefix": identity_prefix,
            "match_all": not terms,
            "text": text,
            "patterns": [f"%{_like_escape(term)}%" for term in terms],
        }
        # Hybrid retrieval only helps a real query: with no embedder or an empty query (match-all), the
        # vector branch adds nothing, so fall back to the proven full-text path (behavior unchanged).
        if self._embedder is None or not terms:
            return self._fts_query(principal, base_params, limit)
        return self._hybrid_query(self._embedder, principal, text, base_params, limit)

    def _fts_query(
        self, principal: Principal | None, base_params: dict[str, Any], limit: int
    ) -> list[Entity]:
        """The M3.1 full-text path: RBAC-filtered in SQL, re-filtered by ``can_read``, batched to ``limit``."""
        results: list[Entity] = []
        offset = 0
        batch = limit
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            while len(results) < limit:
                params = {**base_params, "limit": batch, "offset": offset}
                cur.execute(_QUERY, params)
                rows = cur.fetchall()
                if not rows:
                    break
                for row in rows:
                    entity = _row_to_entity(row)
                    if can_read(principal, entity, self._policy):
                        results.append(entity)
                        if len(results) >= limit:
                            return results
                if len(rows) < batch:
                    break
                offset += len(rows)
        return results

    def _hybrid_query(
        self,
        embedder: EmbeddingProvider,
        principal: Principal | None,
        text: str,
        base_params: dict[str, Any],
        limit: int,
    ) -> list[Entity]:
        """Fuse the full-text and vector rankings (RRF), then apply the ``can_read`` re-filter.

        Both branches are filtered by the *same* RBAC predicate in SQL, so semantic search can never
        surface a row keyword search could not. ``can_read`` remains the final authority.

        FTS candidates are paginated like :meth:`_fts_query` so matches beyond the first candidate
        window are not dropped. If query embedding fails (e.g. Voyage outage), degrades to FTS-only.
        """
        try:
            qvec = _vector_literal(embedder.embed_one(text, input_type="query"))
        except Exception:
            return self._fts_query(principal, base_params, limit)

        pool = max(limit * _CANDIDATE_MULTIPLIER, limit)
        entities_by_id: dict[str, Entity] = {}
        fts_ids: list[str] = []
        vec_ids: list[str] = []

        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            try:
                cur.execute(_VECTOR_QUERY, {**base_params, "qvec": qvec, "limit": pool})
                for row in cur.fetchall():
                    entity = _row_to_entity(row)
                    entities_by_id[entity.id] = entity
                    vec_ids.append(entity.id)
            except pg_errors.DataException:
                return self._fts_query(principal, base_params, limit)

            results: list[Entity] = []
            considered: set[str] = set()
            offset = 0
            batch = limit
            while len(results) < limit:
                params = {**base_params, "limit": batch, "offset": offset}
                cur.execute(_QUERY, params)
                rows = cur.fetchall()
                if not rows:
                    break
                for row in rows:
                    entity = _row_to_entity(row)
                    entities_by_id[entity.id] = entity
                    if entity.id not in fts_ids:
                        fts_ids.append(entity.id)

                fused = _rrf_fuse([fts_ids, vec_ids], k=_RRF_K)
                for entity_id in fused:
                    if entity_id in considered:
                        continue
                    considered.add(entity_id)
                    entity = entities_by_id[entity_id]
                    if can_read(principal, entity, self._policy):
                        results.append(entity)
                        if len(results) >= limit:
                            return results

                if len(rows) < batch:
                    break
                offset += len(rows)

        return results
