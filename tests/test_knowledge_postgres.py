"""Postgres KnowledgeGraph integration tests (run only when DATABASE_URL is set).

Proves the M3.1 guarantees end-to-end against a live Postgres:
1. RBAC scoping is enforced in the query — an org entity is hidden from a guest (IDOR guard),
   world-readable entities are visible to everyone, and the admin wildcard sees all.
2. Writes are durable — an entity upserted by one store instance is read by a fresh one
   (simulated process restart), and upsert replaces by id.
3. Full-text + ILIKE-substring retrieval works, and the backend plugs into the planner so
   `kg_context` is RBAC-scoped exactly like the in-memory backend.
"""

from __future__ import annotations

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.embeddings import DeterministicEmbedder
from atlas.knowledge.extraction import (
    ExtractedEntity,
    ExtractedRelation,
    ExtractionResult,
    FakeExtractor,
)
from atlas.knowledge.ingestion import IngestDocument, IngestionService
from atlas.knowledge.interfaces import Entity, Relation, identity_acl
from atlas.orchestration import build_graph
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.persistence import PostgresKnowledgeGraph
from atlas.tools import ToolRegistry

pytestmark = pytest.mark.integration

MEMBER = Principal(user_id="alice", roles=("member",))  # kg:read:org + kg:read:personal
GUEST = Principal(user_id="bob", roles=("guest",))  # kg:read:personal only
ADMIN = Principal(user_id="root", roles=("admin",))  # wildcard
ANON = Principal.anonymous()  # no roles

_NOTE = Entity(
    id="note-1",
    type="note",
    name="Alice onboarding checklist",
    content="Personal onboarding tasks: set up laptop, read the handbook.",
    acl=("kg:read:personal",),
    scope="personal",
)
_DOC = Entity(
    id="doc-1",
    type="doc",
    name="Q3 revenue figures",
    content="Confidential org revenue numbers for the quarter.",
    acl=("kg:read:org",),
    scope="org",
)
_PUBLIC = Entity(
    id="public-1",
    type="doc",
    name="Company holiday calendar",
    content="Public revenue-day office closures for everyone.",
    acl=(),  # world-readable
    scope="org",
)


def _seed(pool: object) -> PostgresKnowledgeGraph:
    kg = PostgresKnowledgeGraph(pool)  # type: ignore[arg-type]
    for entity in (_NOTE, _DOC, _PUBLIC):
        kg.upsert_entity(entity)
    kg.add_relation(Relation(src_id="note-1", dst_id="doc-1", type="references"))
    return kg


# --- RBAC scoping (the IDOR guard, enforced in the query) --------------------
def test_org_entity_hidden_from_guest_visible_to_member(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    member_ids = {e.id for e in kg.query(MEMBER, "revenue onboarding")}
    guest_ids = {e.id for e in kg.query(GUEST, "revenue onboarding")}
    assert "doc-1" in member_ids  # org doc visible to member
    assert "doc-1" not in guest_ids  # IDOR guard: org doc hidden from guest
    assert "note-1" in guest_ids  # personal note still visible to guest


def test_world_readable_entity_visible_to_everyone(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    for principal in (MEMBER, GUEST, ANON):
        assert "public-1" in {e.id for e in kg.query(principal, "holiday calendar")}


def test_admin_wildcard_sees_all_entities(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    assert {e.id for e in kg.query(ADMIN, "revenue onboarding holiday")} == {
        "note-1",
        "doc-1",
        "public-1",
    }


def test_anonymous_sees_only_world_readable(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    assert {e.id for e in kg.query(ANON, "")} == {"public-1"}


def test_wildcard_grant_reveals_org_entity_via_sql_filter(pg_pool: object) -> None:
    # M3.5 (the critical one): a `kg:read:*` grant must reveal the org-scoped doc-1 over Postgres.
    # The acl `("kg:read:org",)` does NOT exactly overlap `kg:read:*`, so this passes only if the
    # SQL WHERE clause itself honors the wildcard (LIKE prefix) — the Python re-filter alone cannot
    # add back a row the query never fetched.
    kg = _seed(pg_pool)
    kg.bind_policy(InMemoryPolicyStore({"reader": frozenset({"kg:read:*"})}))
    reader = Principal(user_id="carol", roles=("reader",))
    ids = {e.id for e in kg.query(reader, "revenue onboarding holiday")}
    assert ids == {"note-1", "doc-1", "public-1"}  # wildcard reveals both personal + org leaves


def test_wildcard_grant_stays_within_its_prefix(pg_pool: object) -> None:
    # A `kg:read:*` grant must NOT reveal an entity gated on a different prefix (no over-include).
    kg = _seed(pg_pool)
    secret = Entity(
        id="secret-1",
        type="doc",
        name="Quarterly revenue secret",
        content="kg:write protected revenue plan",
        acl=("kg:write:org",),
        scope="org",
    )
    kg.upsert_entity(secret)
    kg.bind_policy(InMemoryPolicyStore({"reader": frozenset({"kg:read:*"})}))
    reader = Principal(user_id="carol", roles=("reader",))
    assert "secret-1" not in {e.id for e in kg.query(reader, "revenue")}


# --- retrieval semantics ----------------------------------------------------
def test_full_text_match_on_a_single_term(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    assert {e.id for e in kg.query(MEMBER, "onboarding")} == {"note-1"}


def test_ilike_fallback_matches_partial_term(pg_pool: object) -> None:
    # "reven" is not a tsquery word match for "revenue"; the ILIKE substring fallback catches it.
    kg = _seed(pg_pool)
    assert "doc-1" in {e.id for e in kg.query(MEMBER, "reven")}


def test_empty_query_returns_all_readable_up_to_limit(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    assert {e.id for e in kg.query(MEMBER, "")} == {"note-1", "doc-1", "public-1"}
    assert len(kg.query(MEMBER, "", limit=1)) == 1


def _seed_dense_foreign_pkg(pg_pool: object) -> PostgresKnowledgeGraph:
    kg = PostgresKnowledgeGraph(pg_pool)  # type: ignore[arg-type]
    kg.upsert_entity(_DOC)
    for index in range(6):
        kg.upsert_entity(
            Entity(
                id=f"a-pkg-{index:02d}",
                type="note",
                name=f"Foreign PKG {index}",
                content="private personal knowledge",
                acl=(identity_acl(f"other-{index}"),),
                scope="personal",
            )
        )
    return kg


def test_admin_query_limit_not_displaced_by_foreign_pkg(pg_pool: object) -> None:
    kg = _seed_dense_foreign_pkg(pg_pool)
    ids = {e.id for e in kg.query(ADMIN, "", limit=5)}
    assert "doc-1" in ids
    assert not any(entity_id.startswith("a-pkg-") for entity_id in ids)


def test_wildcard_reader_query_limit_not_displaced_by_foreign_pkg(pg_pool: object) -> None:
    kg = _seed_dense_foreign_pkg(pg_pool)
    kg.bind_policy(InMemoryPolicyStore({"reader": frozenset({"kg:read:*"})}))
    reader = Principal(user_id="carol", roles=("reader",))
    ids = {e.id for e in kg.query(reader, "", limit=5)}
    assert "doc-1" in ids
    assert not any(entity_id.startswith("a-pkg-") for entity_id in ids)


# --- durability + upsert ----------------------------------------------------
def test_entity_is_durable_across_a_fresh_store_instance(pg_pool: object) -> None:
    _seed(pg_pool)
    # A brand-new store over the same DB (no re-setup) reads the persisted entities + relations.
    reloaded = PostgresKnowledgeGraph(pg_pool, setup=False)  # type: ignore[arg-type]
    assert {e.id for e in reloaded.query(MEMBER, "")} == {"note-1", "doc-1", "public-1"}
    assert any(r.src_id == "note-1" and r.dst_id == "doc-1" for r in reloaded.relations())


def test_upsert_replaces_entity_by_id(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    kg.upsert_entity(_DOC.model_copy(update={"name": "Q4 revenue figures"}))
    matches = kg.query(MEMBER, "revenue")
    docs = [e for e in matches if e.id == "doc-1"]
    assert len(docs) == 1  # replaced, not duplicated
    assert docs[0].name == "Q4 revenue figures"


# --- planner wiring (RBAC-scoped kg_context flows into state) ----------------
def _search_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def test_planner_context_is_rbac_scoped_with_postgres_backend(pg_pool: object) -> None:
    kg = _seed(pg_pool)
    atlas = build_graph(
        plan_fn=_search_plan,
        knowledge=kg,
        policy=InMemoryPolicyStore(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config: RunnableConfig = {"configurable": {"thread_id": "kg-pg-guest"}}
    result = atlas.graph.invoke(
        initial_state("find the revenue and onboarding info", principal=GUEST), config=config
    )
    ids = {e.id for e in result["kg_context"]}
    assert "doc-1" not in ids  # org doc never retrieved for a guest
    assert "note-1" in ids


# --- M4.6 pgvector hybrid retrieval -----------------------------------------
# The deterministic embedder is not semantically meaningful, so these tests assert the *plumbing* and
# the *security invariant* of the vector path. Real semantic-quality is validated manually with a live
# VOYAGE_API_KEY. The embedder is a pure function: querying a row's exact embedded text yields an
# identical vector (cosine distance 0), which lets us prove the vector branch influences ranking.
_EMBED_DIM = 1024


def _seed_with_embedder(pg_pool: object) -> PostgresKnowledgeGraph:
    kg = PostgresKnowledgeGraph(pg_pool, embedder=DeterministicEmbedder(_EMBED_DIM))  # type: ignore[arg-type]
    for entity in (_NOTE, _DOC, _PUBLIC):
        kg.upsert_entity(entity)
    return kg


def test_embedding_is_populated_on_upsert(pg_pool: object) -> None:
    _seed_with_embedder(pg_pool)
    with pg_pool.connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute("SELECT count(*) AS n FROM atlas_kg_entities WHERE embedding IS NOT NULL")
        assert cur.fetchone()["n"] == 3  # every upserted entity got a vector


def test_hybrid_query_org_doc_hidden_from_guest_visible_to_member(pg_pool: object) -> None:
    # The IDOR guard on the vector path: the same RBAC predicate filters FTS and vector branches alike.
    kg = _seed_with_embedder(pg_pool)
    member_ids = {e.id for e in kg.query(MEMBER, "revenue onboarding")}
    guest_ids = {e.id for e in kg.query(GUEST, "revenue onboarding")}
    assert "doc-1" in member_ids
    assert "doc-1" not in guest_ids  # semantic search cannot widen read access
    assert "note-1" in guest_ids


def test_vector_branch_ranks_exact_embedded_text_first(pg_pool: object) -> None:
    kg = _seed_with_embedder(pg_pool)
    query_text = f"{_DOC.name}\n{_DOC.content}"  # identical to _DOC's embedded text -> distance 0
    top = kg.query(ADMIN, query_text, limit=3)
    assert top and top[0].id == "doc-1"


def test_fts_fallback_when_store_has_no_embedder(pg_pool: object) -> None:
    kg = _seed(pg_pool)  # no embedder => behavior identical to the M3.1 full-text store
    assert {e.id for e in kg.query(MEMBER, "onboarding")} == {"note-1"}


class _QueryFailingEmbedder(DeterministicEmbedder):
    """Fails query embedding only; document embedding still works for upsert."""

    def embed(self, texts, *, input_type="document"):  # type: ignore[no-untyped-def]
        if input_type == "query":
            raise ConnectionError("embedding provider unavailable")
        return super().embed(texts, input_type=input_type)


class _UpsertFailingEmbedder(DeterministicEmbedder):
    """Fails document embedding; upsert should persist the entity without a vector."""

    def embed(self, texts, *, input_type="document"):  # type: ignore[no-untyped-def]
        raise ConnectionError("embedding provider unavailable")


def test_hybrid_query_falls_back_to_fts_when_embedding_fails(pg_pool: object) -> None:
    kg = PostgresKnowledgeGraph(pg_pool, embedder=_QueryFailingEmbedder(_EMBED_DIM))  # type: ignore[arg-type]
    for entity in (_NOTE, _DOC, _PUBLIC):
        kg.upsert_entity(entity)
    # Query embedding fails, but FTS still finds the personal note.
    assert {e.id for e in kg.query(MEMBER, "onboarding")} == {"note-1"}


def test_upsert_persists_entity_when_embedding_fails(pg_pool: object) -> None:
    kg = PostgresKnowledgeGraph(pg_pool, embedder=_UpsertFailingEmbedder(_EMBED_DIM))  # type: ignore[arg-type]
    kg.upsert_entity(_NOTE)
    with pg_pool.connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute("SELECT id, embedding FROM atlas_kg_entities WHERE id = %s", ("note-1",))
        row = cur.fetchone()
    assert row["id"] == "note-1"
    assert row["embedding"] is None


def test_setup_backfills_null_embeddings(pg_pool: object) -> None:
    _seed(pg_pool)  # no embedder — rows exist without vectors
    PostgresKnowledgeGraph(pg_pool, embedder=DeterministicEmbedder(_EMBED_DIM))  # type: ignore[arg-type]
    with pg_pool.connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute("SELECT count(*) AS n FROM atlas_kg_entities WHERE embedding IS NOT NULL")
        assert cur.fetchone()["n"] == 3


def test_setup_migrates_embedding_dim(pg_pool: object) -> None:
    from atlas.persistence.knowledge_store import _CREATE_TABLES, _vector_literal

    old_dim = 64
    new_dim = 1024
    with pg_pool.connection() as conn:  # type: ignore[attr-defined]
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute(_CREATE_TABLES)
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute(f"ALTER TABLE atlas_kg_entities ADD COLUMN embedding vector({old_dim})")
        embedder_old = DeterministicEmbedder(old_dim)
        vec = embedder_old.embed_one(f"{_DOC.name}\n{_DOC.content}", input_type="document")
        conn.execute(
            """
            INSERT INTO atlas_kg_entities (id, type, name, content, acl, scope, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s::vector)
            """,
            (
                _DOC.id,
                _DOC.type,
                _DOC.name,
                _DOC.content,
                list(_DOC.acl),
                _DOC.scope,
                _vector_literal(vec),
            ),
        )
    kg = PostgresKnowledgeGraph(pg_pool, embedder=DeterministicEmbedder(new_dim))  # type: ignore[arg-type]
    query_text = f"{_DOC.name}\n{_DOC.content}"
    top = kg.query(ADMIN, query_text, limit=1)
    assert top and top[0].id == "doc-1"


def test_hybrid_query_paginates_fts_beyond_initial_candidate_window(pg_pool: object) -> None:
    # Regression: a single LIMIT pool fetch at offset=0 capped FTS-only matches at pool rows even when
    # more than pool readable hits exist. Pagination must keep scanning until ``limit`` is filled.
    kg = PostgresKnowledgeGraph(pg_pool, embedder=DeterministicEmbedder(_EMBED_DIM))  # type: ignore[arg-type]
    for i in range(50):
        kg.upsert_entity(
            Entity(
                id=f"bulk-{i:02d}",
                type="note",
                name=f"bulk pagination token {i}",
                content="shared paginationtoken for hybrid fts window regression",
                acl=("kg:read:org",),
                scope="org",
            )
        )
    # Strip embeddings so the vector branch contributes nothing; only FTS can surface rows.
    with pg_pool.connection() as conn:  # type: ignore[attr-defined]
        conn.execute("UPDATE atlas_kg_entities SET embedding = NULL")
    hits = kg.query(MEMBER, "paginationtoken", limit=45)
    assert len(hits) == 45


# --- M4.5: LLM entity/relation extraction over the Postgres ingestion path ---
def _extraction_result() -> ExtractionResult:
    return ExtractionResult(
        entities=(
            ExtractedEntity(name="Ada Lovelace", type="person"),
            ExtractedEntity(name="Project Atlas", type="project"),
        ),
        relations=(
            ExtractedRelation(
                src_name="Ada Lovelace",
                src_type="person",
                dst_name="Project Atlas",
                dst_type="project",
                type="works_on",
            ),
        ),
    )


def _ingestion(pool: object, principal_policy: InMemoryPolicyStore) -> IngestionService:
    kg = PostgresKnowledgeGraph(pool, policy=principal_policy)  # type: ignore[arg-type]
    return IngestionService(
        kg,
        principal_policy,
        InMemoryAuditLog(),
        extractor=FakeExtractor(_extraction_result()),
    )


def test_extracted_entities_and_relations_persist_to_postgres(pg_pool: object) -> None:
    policy = InMemoryPolicyStore()
    service = _ingestion(pg_pool, policy)
    result = service.ingest(
        MEMBER, IngestDocument(text="Ada works on Atlas", title="memo", scope="personal")
    )
    assert result.extracted_entity_count == 2
    kg = PostgresKnowledgeGraph(pg_pool, policy=policy)  # type: ignore[arg-type]
    types = {e.type for e in kg.query(MEMBER, "Ada Atlas", limit=50)}
    assert {"doc", "person", "project"} <= types
    assert "works_on" in {r.type for r in kg.relations()}
    assert "mentions" in {r.type for r in kg.relations()}


def test_extracted_personal_entities_hidden_from_other_users(pg_pool: object) -> None:
    # IDOR guard on the *extracted* nodes: a personal ingest stamps the owner's identity ACL, so the
    # person/project nodes are invisible to another user (and even to admin's wildcard).
    policy = InMemoryPolicyStore()
    service = _ingestion(pg_pool, policy)
    service.ingest(MEMBER, IngestDocument(text="Ada works on Atlas", title="memo"))

    kg = PostgresKnowledgeGraph(pg_pool, policy=policy)  # type: ignore[arg-type]
    owner_concepts = {e.id for e in kg.query(MEMBER, "Ada Atlas", limit=50) if e.type != "doc"}
    assert owner_concepts  # owner sees the extracted concepts
    assert {e.id for e in kg.query(GUEST, "Ada Atlas", limit=50) if e.type != "doc"} == set()
    assert {e.id for e in kg.query(ADMIN, "Ada Atlas", limit=50) if e.type != "doc"} == set()


def test_extracted_org_entities_visible_to_org_readers(pg_pool: object) -> None:
    policy = InMemoryPolicyStore()
    service = _ingestion(pg_pool, policy)
    service.ingest(ADMIN, IngestDocument(text="Ada works on Atlas", title="memo", scope="org"))

    kg = PostgresKnowledgeGraph(pg_pool, policy=policy)  # type: ignore[arg-type]
    member_concepts = {e.type for e in kg.query(MEMBER, "Ada Atlas", limit=50) if e.type != "doc"}
    assert {"person", "project"} <= member_concepts  # org reader sees org-scoped concepts
    assert {e.id for e in kg.query(GUEST, "Ada Atlas", limit=50) if e.type != "doc"} == set()


def test_reingest_does_not_duplicate_extracted_nodes(pg_pool: object) -> None:
    policy = InMemoryPolicyStore()
    service = _ingestion(pg_pool, policy)
    doc = IngestDocument(text="Ada works on Atlas", title="memo", source_id="src-1")
    service.ingest(MEMBER, doc)
    kg = PostgresKnowledgeGraph(pg_pool, policy=policy)  # type: ignore[arg-type]
    before = {e.id for e in kg.query(MEMBER, "", limit=200)}
    before_relations = len(kg.relations())
    service.ingest(MEMBER, doc)
    after = {e.id for e in kg.query(MEMBER, "", limit=200)}
    after_relations = len(kg.relations())
    assert before == after  # deterministic ids => idempotent upsert, no duplicate growth
    # Relations are idempotent too: the ON CONFLICT (src_id, dst_id, type) DO NOTHING insert means
    # re-ingesting the same document re-adds no edges (the table does not grow unbounded).
    assert before_relations == after_relations


def test_setup_dedupes_legacy_duplicate_relations(pg_pool: object) -> None:
    from atlas.persistence.knowledge_store import _CREATE_TABLES

    with pg_pool.connection() as conn:  # type: ignore[attr-defined]
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute(_CREATE_TABLES)
        conn.execute(
            "INSERT INTO atlas_kg_relations (src_id, dst_id, type) VALUES (%s, %s, %s)",
            ("src-a", "dst-b", "references"),
        )
        conn.execute(
            "INSERT INTO atlas_kg_relations (src_id, dst_id, type) VALUES (%s, %s, %s)",
            ("src-a", "dst-b", "references"),
        )

    PostgresKnowledgeGraph(pg_pool, setup=True)  # type: ignore[arg-type]

    with pg_pool.connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute(
            "SELECT count(*) AS n FROM atlas_kg_relations "
            "WHERE src_id = %s AND dst_id = %s AND type = %s",
            ("src-a", "dst-b", "references"),
        )
        assert cur.fetchone()["n"] == 1

    kg = PostgresKnowledgeGraph(pg_pool, setup=False)  # type: ignore[arg-type]
    before = len(kg.relations())
    kg.add_relation(Relation(src_id="src-a", dst_id="dst-b", type="references"))
    assert len(kg.relations()) == before  # idempotent — ON CONFLICT DO NOTHING
