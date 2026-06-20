"""Knowledge layer interfaces.

The :class:`KnowledgeGraph` is atlas's long-term, compounding memory. Reads are **RBAC-scoped**: a
query returns only entities the calling :class:`~atlas.governance.rbac.Principal` is permitted to
read (``can_read``), so sensitive content is filtered out *before* it can reach the planner or the
LLM. The in-memory implementation lives in :mod:`atlas.knowledge.memory_store`; a concrete backend
(Neo4j / pgvector) slots behind this same interface in M3.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from atlas.governance.policy import DEFAULT_POLICY, PolicyStore
from atlas.governance.rbac import Principal


class Entity(BaseModel):
    """A node in the knowledge graph. Immutable."""

    model_config = ConfigDict(frozen=True)

    id: str
    type: str  # e.g. "note", "doc", "person", "project"
    name: str
    content: str = ""
    # acl: permission strings; the principal needs ANY one to read this entity. An empty acl means
    # "world-readable". Deliberately simple for M2.2 — evolves into a richer ACL model in M3/M4.
    acl: tuple[str, ...] = Field(default_factory=tuple)
    scope: Literal["personal", "org"] = "org"


class Relation(BaseModel):
    """A directed edge between two entities. Immutable."""

    model_config = ConfigDict(frozen=True)

    src_id: str
    dst_id: str
    type: str


def can_read(
    principal: Principal | None, entity: Entity, policy: PolicyStore | None = None
) -> bool:
    """Return True iff ``principal`` may read ``entity`` (fail-closed).

    An entity with no acl is world-readable. Otherwise the principal must hold at least one of the
    acl's permissions per the ``policy`` store (defaults to the in-memory built-in policy when none
    is injected); if none are satisfied the entity is treated as unreadable (and omitted).
    """
    if not entity.acl:
        return True
    store = policy or DEFAULT_POLICY
    return any(store.can(principal, permission) for permission in entity.acl)


class KnowledgeGraph(abc.ABC):
    """RBAC-scoped knowledge store. Implementations must never return entities the principal cannot
    read from :meth:`query`.
    """

    @abc.abstractmethod
    def query(self, principal: Principal | None, text: str, *, limit: int = 5) -> list[Entity]:
        """Return up to ``limit`` entities relevant to ``text`` that ``principal`` may read."""
        raise NotImplementedError

    @abc.abstractmethod
    def upsert_entity(self, entity: Entity) -> None:
        """Insert or replace an entity by id."""
        raise NotImplementedError

    @abc.abstractmethod
    def add_relation(self, relation: Relation) -> None:
        """Add a directed relation between two entities."""
        raise NotImplementedError

    @abc.abstractmethod
    def relations(self) -> Sequence[Relation]:
        """Return all relations (used by tests/inspection)."""
        raise NotImplementedError

    def bind_policy(self, policy: PolicyStore) -> None:
        """Attach the store governing RBAC read filtering (used by ``build_graph`` wiring)."""
        raise NotImplementedError
