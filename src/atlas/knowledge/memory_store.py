"""In-memory KnowledgeGraph (the dev/test stub).

Naive case-insensitive keyword matching over an entity's name + content, **then** filtered by
``can_read`` and capped at ``limit``. This is intentionally dumb — a grounding hook, not a retrieval
system. A real backend (Neo4j / pgvector with vector search) replaces it behind the same interface
in M3.
"""

from __future__ import annotations

from collections.abc import Sequence

from atlas.governance.policy import PolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity, KnowledgeGraph, Relation, can_read


class InMemoryKnowledgeGraph(KnowledgeGraph):
    def __init__(self, policy: PolicyStore | None = None) -> None:
        self._entities: dict[str, Entity] = {}
        self._relations: list[Relation] = []
        self._policy = policy  # None => can_read uses the built-in default policy

    def upsert_entity(self, entity: Entity) -> None:
        self._entities[entity.id] = entity

    def add_relation(self, relation: Relation) -> None:
        # Dedup on (src_id, dst_id, type) to mirror the Postgres backend's
        # ``ON CONFLICT (src_id, dst_id, type) DO NOTHING``: re-ingesting the same document must not
        # grow the edge list. Append-only otherwise, preserving insertion order for ``relations()``.
        key = (relation.src_id, relation.dst_id, relation.type)
        if any((r.src_id, r.dst_id, r.type) == key for r in self._relations):
            return
        self._relations.append(relation)

    def relations(self) -> Sequence[Relation]:
        return tuple(self._relations)

    def bind_policy(self, policy: PolicyStore) -> None:
        self._policy = policy

    def query(self, principal: Principal | None, text: str, *, limit: int = 5) -> list[Entity]:
        terms = [term for term in text.lower().split() if term]
        matches: list[Entity] = []
        for entity in self._entities.values():
            # RBAC filter first: an unreadable entity is never considered, never returned.
            if not can_read(principal, entity, self._policy):
                continue
            haystack = f"{entity.name}\n{entity.content}".lower()
            if not terms or any(term in haystack for term in terms):
                matches.append(entity)
        return matches[:limit]


def seed_demo_graph() -> InMemoryKnowledgeGraph:
    """A tiny graph for demos/tests: one personal note and one org-restricted doc."""
    graph = InMemoryKnowledgeGraph()
    graph.upsert_entity(
        Entity(
            id="note-1",
            type="note",
            name="Alice onboarding checklist",
            content="Personal onboarding tasks: set up laptop, read the handbook.",
            acl=("kg:read:personal",),
            scope="personal",
        )
    )
    graph.upsert_entity(
        Entity(
            id="doc-1",
            type="doc",
            name="Q3 revenue figures",
            content="Confidential org revenue numbers for the quarter.",
            acl=("kg:read:org",),
            scope="org",
        )
    )
    graph.add_relation(Relation(src_id="note-1", dst_id="doc-1", type="references"))
    return graph
