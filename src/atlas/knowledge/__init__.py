"""Knowledge layer — the agent's RBAC-scoped, compounding long-term memory.

M2.2b ships a typed interface + an in-memory stub; a concrete backend (Neo4j / pgvector) slots
behind :class:`KnowledgeGraph` in M3.
"""

from atlas.knowledge.interfaces import Entity, KnowledgeGraph, Relation, can_read
from atlas.knowledge.memory_store import InMemoryKnowledgeGraph, seed_demo_graph

__all__ = [
    "Entity",
    "InMemoryKnowledgeGraph",
    "KnowledgeGraph",
    "Relation",
    "can_read",
    "seed_demo_graph",
]
