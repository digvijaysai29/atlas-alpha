"""Durable, RBAC-scoped knowledge retrieval over Postgres (requires Postgres).

  docker compose up -d
  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas
  uv run python scripts/demo_knowledge_postgres.py

Seeds a Postgres-backed knowledge graph (a personal note, an org-restricted doc, and a
world-readable doc), then runs the same request as three principals and shows that RBAC scoping is
enforced *in the query* — the org doc never reaches a guest, while the durable store survives a
fresh connection (simulated restart).
"""

from __future__ import annotations

import os
import sys

from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity, Relation
from atlas.orchestration.graph import _pg_pool
from atlas.persistence import PostgresKnowledgeGraph

_SEED = (
    Entity(
        id="note-1",
        type="note",
        name="Alice onboarding checklist",
        content="Personal onboarding tasks: set up laptop, read the handbook.",
        acl=("kg:read:personal",),
        scope="personal",
    ),
    Entity(
        id="doc-1",
        type="doc",
        name="Q3 revenue figures",
        content="Confidential org revenue numbers for the quarter.",
        acl=("kg:read:org",),
        scope="org",
    ),
    Entity(
        id="public-1",
        type="doc",
        name="Company holiday calendar",
        content="Public office closures for everyone.",
        acl=(),  # world-readable
        scope="org",
    ),
)


def _run(kg: PostgresKnowledgeGraph, label: str, principal: Principal) -> None:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    for entity in kg.query(principal, "revenue onboarding holiday"):
        print(f"  • [{entity.scope:8}] {entity.id}  {entity.name}")


def main() -> None:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set. Start Postgres and export it, e.g.:")
        print("  docker compose up -d")
        print("  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas")
        sys.exit(0)

    pool = _pg_pool(url)
    # Clean slate so the demo is deterministic.
    with pool.connection() as conn:
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")

    try:
        kg = PostgresKnowledgeGraph(pool)
        for entity in _SEED:
            kg.upsert_entity(entity)
        kg.add_relation(Relation(src_id="note-1", dst_id="doc-1", type="references"))

        member = Principal(user_id="alice", roles=("member",))
        _run(kg, "MEMBER  (kg:read:org + kg:read:personal)", member)
        _run(kg, "GUEST   (kg:read:personal only)", Principal(user_id="bob", roles=("guest",)))
        _run(kg, "ANON    (no roles)", Principal.anonymous())

        print(
            f"\n{'=' * 72}\nDurability: a fresh store over the same DB (simulated restart)\n{'=' * 72}"
        )
        reloaded = PostgresKnowledgeGraph(pool, setup=False)
        ids = sorted(e.id for e in reloaded.query(member, ""))
        print(f"  entities still readable by member: {ids}")
    finally:
        pool.close()
        _pg_pool.cache_clear()


if __name__ == "__main__":
    main()
