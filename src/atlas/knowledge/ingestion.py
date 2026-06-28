"""Deterministic knowledge ingestion — the KG *write* path (M4.4).

This is the missing half of the knowledge layer: the read path (:func:`atlas.knowledge.can_read`,
the planner's RBAC-scoped ``query``) already exists, but nothing populated the graph. The
:class:`IngestionService` turns a raw document into RBAC-scoped, deduplicated
:class:`~atlas.knowledge.interfaces.Entity` nodes so the Personal/Organizational Knowledge Graph
actually *compounds* over time.

Security posture (fail-closed, mirrors the rest of atlas):

- **The server resolves scope + ACL** from the authenticated principal. The caller may *request*
  ``personal`` or ``org``, but never dictates the ACL: ``personal`` is stamped with a per-user
  identity ACL (PKG isolation); ``org`` requires the ``kg:write:org`` permission.
- **Anonymous principal, missing ``kg:write:org``, or an ambiguous scope/ACL combination ⇒
  :class:`IngestionDenied`** — nothing is written.
- **Deterministic entity ids** (``{scope}:{owner}:{source_id}:{chunk}``) make re-ingesting the same
  document an idempotent upsert, so the graph never grows duplicates.
- **No document content** ever reaches logs or the audit trail (counts + scope only).

This module is intentionally deterministic and dependency-free (a small fixed-window chunker, no LLM
and no embeddings) so the whole write path is covered by the blocking deterministic eval gate. LLM
entity/relation extraction and pgvector semantic retrieval are later milestones behind this same API.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from atlas.governance.audit import AuditLog
from atlas.governance.policy import PolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity, KnowledgeGraph, identity_acl

logger = logging.getLogger("atlas.knowledge.ingestion")

# Fixed-window chunking. Deliberately simple and deterministic (no magic numbers inline). Smarter,
# boundary-aware or semantic chunking is a later milestone — it must not compromise determinism here.
DEFAULT_CHUNK_SIZE = 2000
DEFAULT_CHUNK_OVERLAP = 200

# The permission required to write organization-scoped (OKG) knowledge. Satisfied only by a role that
# holds it (admin's ``*`` does by default); members/guests are denied — fail-closed.
ORG_WRITE_PERMISSION = "kg:write:org"
# Default read ACL applied to org-scoped entities when the caller does not specify one.
DEFAULT_ORG_ACL: tuple[str, ...] = ("kg:read:org",)

Scope = Literal["personal", "org"]


class IngestDocument(BaseModel):
    """A document submitted for ingestion. Immutable; validated at the boundary."""

    model_config = ConfigDict(frozen=True)

    text: str = Field(min_length=1, description="The raw document text to chunk and store.")
    title: str = Field(
        min_length=1, description="Human-readable title; also used to derive a stable source id."
    )
    type: str = "doc"
    scope: Scope = "personal"
    # A stable identifier for the source document. When omitted it is derived from the title so
    # re-ingesting the "same" document is idempotent. Two different sources should pass distinct ids.
    source_id: str | None = None
    # Optional explicit read ACL for ``org`` scope only (e.g. a narrower team grant). Supplying it for
    # ``personal`` scope is ambiguous and rejected (the identity ACL is always authoritative there).
    org_acl: tuple[str, ...] | None = None


class IngestionResult(BaseModel):
    """The outcome of an ingestion: which entities were written. Immutable."""

    model_config = ConfigDict(frozen=True)

    entity_ids: tuple[str, ...]
    chunk_count: int
    scope: str
    source_id: str


class IngestionDenied(Exception):
    """Raised when ingestion is refused (fail-closed). The message is safe to surface (no content)."""


def chunk_text(
    text: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
) -> list[str]:
    """Split ``text`` into deterministic fixed-size character windows with ``overlap`` carry-over.

    Returns ``[]`` for whitespace-only input and a single chunk when the text fits in one window.
    Pure and deterministic: the same input always yields the same chunks (required by the eval gate).
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if not 0 <= overlap < chunk_size:
        raise ValueError("overlap must be in [0, chunk_size)")
    normalized = text.strip()
    if not normalized:
        return []
    if len(normalized) <= chunk_size:
        return [normalized]
    step = chunk_size - overlap
    chunks: list[str] = []
    start = 0
    length = len(normalized)
    while start < length:
        chunks.append(normalized[start : start + chunk_size])
        if start + chunk_size >= length:
            break
        start += step
    return chunks


def _source_id_for(document: IngestDocument) -> str:
    """A stable, opaque source id: the caller's value, else a hash of the title (idempotency key)."""
    if document.source_id:
        return document.source_id
    return hashlib.sha256(document.title.encode("utf-8")).hexdigest()[:16]


class IngestionService:
    """Deterministic, RBAC-aware writer for the knowledge graph.

    Collaborators are injected (the same KG, policy, and audit the graph already uses), mirroring the
    rest of atlas's dependency-injection style.
    """

    def __init__(
        self,
        knowledge: KnowledgeGraph,
        policy: PolicyStore,
        audit: AuditLog | None = None,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        chunk_overlap: int = DEFAULT_CHUNK_OVERLAP,
    ) -> None:
        self._knowledge = knowledge
        self._policy = policy
        self._audit = audit
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap

    def ingest(self, principal: Principal | None, document: IngestDocument) -> IngestionResult:
        """Write ``document`` into the KG as scoped, deduplicated entities (fail-closed).

        Raises :class:`IngestionDenied` for an anonymous principal, an unauthorized ``org`` write, or
        an ambiguous scope/ACL combination — without writing anything.
        """
        if principal is None or principal == Principal.anonymous():
            raise IngestionDenied("authentication required to ingest knowledge")

        scope, acl, owner_segment = self._resolve_scope_acl(principal, document)
        source_id = _source_id_for(document)
        chunks = chunk_text(document.text, chunk_size=self._chunk_size, overlap=self._chunk_overlap)

        entity_ids: list[str] = []
        for index, chunk in enumerate(chunks):
            entity = Entity(
                id=f"{owner_segment}:{source_id}:{index:04d}",
                type=document.type,
                name=f"{document.title} [{index}]",
                content=chunk,
                acl=acl,
                scope=scope,
            )
            self._knowledge.upsert_entity(entity)
            entity_ids.append(entity.id)

        if self._audit is not None:
            self._audit.ingested(
                source_id=source_id,
                scope=scope,
                entity_count=len(entity_ids),
                actor=principal.user_id,
            )
        logger.info(
            "ingested %d chunk(s) scope=%s source=%s actor=%s",
            len(entity_ids),
            scope,
            source_id,
            principal.user_id,
        )
        return IngestionResult(
            entity_ids=tuple(entity_ids),
            chunk_count=len(entity_ids),
            scope=scope,
            source_id=source_id,
        )

    def _resolve_scope_acl(
        self, principal: Principal, document: IngestDocument
    ) -> tuple[Scope, tuple[str, ...], str]:
        """Resolve ``(scope, acl, owner_segment)`` from the principal + request, server-side.

        ``owner_segment`` namespaces the entity id so two users ingesting the same title never collide
        (their PKGs stay separate). Authorization is data-driven, never derived from document content.
        """
        if document.scope == "personal":
            if document.org_acl is not None:
                raise IngestionDenied("org_acl is not valid for personal scope")
            return (
                "personal",
                (identity_acl(principal.user_id),),
                f"personal:{principal.user_id}",
            )
        if document.scope == "org":
            if not self._policy.can(principal, ORG_WRITE_PERMISSION):
                raise IngestionDenied("principal is not permitted to write organization knowledge")
            acl = document.org_acl or DEFAULT_ORG_ACL
            return "org", acl, "org"
        # Unreachable via the validated Literal, but fail-closed if ever reached.
        raise IngestionDenied("unknown ingestion scope")
