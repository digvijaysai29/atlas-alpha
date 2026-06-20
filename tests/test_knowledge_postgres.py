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
from atlas.governance import InMemoryPolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity, Relation
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
