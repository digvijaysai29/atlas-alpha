"""Knowledge layer — the agent's RBAC-scoped, compounding long-term memory.

M2.2b ships a typed interface + an in-memory stub; a concrete backend (Neo4j / pgvector) slots
behind :class:`KnowledgeGraph` in M3.
"""

from atlas.knowledge.ingestion import (
    IngestDocument,
    IngestionDenied,
    IngestionResult,
    IngestionService,
    chunk_text,
)
from atlas.knowledge.interfaces import (
    Entity,
    KnowledgeGraph,
    Relation,
    can_read,
    identity_acl,
)
from atlas.knowledge.memory_store import InMemoryKnowledgeGraph, seed_demo_graph

__all__ = [
    "Entity",
    "InMemoryKnowledgeGraph",
    "IngestDocument",
    "IngestionDenied",
    "IngestionResult",
    "IngestionService",
    "KnowledgeGraph",
    "Relation",
    "can_read",
    "chunk_text",
    "identity_acl",
    "seed_demo_graph",
]
