"""Knowledge layer — the agent's RBAC-scoped, compounding long-term memory.

M2.2b ships a typed interface + an in-memory stub; a concrete backend (Neo4j / pgvector) slots
behind :class:`KnowledgeGraph` in M3.
"""

from atlas.knowledge.extraction import (
    DeterministicExtractor,
    EntityExtractor,
    ExtractedEntity,
    ExtractedRelation,
    ExtractionResult,
    FakeExtractor,
    LLMExtractor,
    make_extractor,
)
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
    "DeterministicExtractor",
    "Entity",
    "EntityExtractor",
    "ExtractedEntity",
    "ExtractedRelation",
    "ExtractionResult",
    "FakeExtractor",
    "InMemoryKnowledgeGraph",
    "IngestDocument",
    "IngestionDenied",
    "IngestionResult",
    "IngestionService",
    "KnowledgeGraph",
    "LLMExtractor",
    "Relation",
    "can_read",
    "chunk_text",
    "identity_acl",
    "make_extractor",
    "seed_demo_graph",
]
