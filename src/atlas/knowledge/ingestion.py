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

The deterministic core (a small fixed-window chunker, no LLM, no embeddings) is always present so the
whole write path stays covered by the blocking deterministic eval gate. **LLM entity/relation
extraction (M4.5)** is an *optional* enrichment layered on top: when an :class:`EntityExtractor` is
injected, the service additionally writes typed concept entities + relations the model proposes — but
the model output never influences authorization (scope/ACL stay server-resolved) and never breaks the
core write (extraction failures degrade to chunks-only). With the default deterministic no-op
extractor the behavior is byte-for-byte M4.4, so the eval gate is unaffected. pgvector semantic
retrieval (M4.6) is a separate store-side concern behind the same KG interface.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from atlas.governance.audit import AuditLog
from atlas.governance.policy import PolicyStore
from atlas.governance.rbac import Principal
from atlas.knowledge.extraction import EntityExtractor, ExtractedRelation, ExtractionResult
from atlas.knowledge.interfaces import Entity, KnowledgeGraph, Relation, identity_acl

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

# Caps on how much *untrusted* extractor output is persisted per document (defense-in-depth against a
# runaway or adversarial model). Overridable from settings; these are the conservative defaults.
DEFAULT_MAX_EXTRACTED_ENTITIES = 64
DEFAULT_MAX_EXTRACTED_RELATIONS = 128
# Relation label linking a source document's chunks to a concept the extractor found in them.
MENTIONS_RELATION = "mentions"

Scope = Literal["personal", "org"]

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class IngestDocument(BaseModel):
    """A document submitted for ingestion. Immutable; validated at the boundary."""

    model_config = ConfigDict(frozen=True)

    text: NonEmptyText = Field(description="The raw document text to chunk and store.")
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
    # M4.5 enrichment counts: None when extraction is disabled (M4.4); 0 when enrichment ran but
    # found nothing or degraded to chunks-only.
    extracted_entity_count: int | None = None
    relation_count: int | None = None


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
        extractor: EntityExtractor | None = None,
        max_extracted_entities: int = DEFAULT_MAX_EXTRACTED_ENTITIES,
        max_extracted_relations: int = DEFAULT_MAX_EXTRACTED_RELATIONS,
    ) -> None:
        self._knowledge = knowledge
        self._policy = policy
        self._audit = audit
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        # ``extractor=None`` => no enrichment (pure M4.4). The graph factory injects an OpenRouter-
        # backed extractor only when extraction is enabled.
        self._extractor = extractor
        if max_extracted_entities <= 0 or max_extracted_relations <= 0:
            raise ValueError("extraction caps must be positive")
        self._max_extracted_entities = max_extracted_entities
        self._max_extracted_relations = max_extracted_relations

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
        if not chunks:
            raise IngestionDenied("document text is empty")

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

        # M4.5 enrichment: layer typed entities + relations on top of the deterministic chunks. The
        # scope/acl resolved above are passed in verbatim — the extractor never influences authz.
        extracted_ids, relation_count = self._enrich_with_extraction(
            document=document,
            scope=scope,
            acl=acl,
            owner_segment=owner_segment,
            source_id=source_id,
            chunk_entity_ids=entity_ids,
        )
        if self._extractor is None:
            extracted_count: int | None = None
            relation_count_out: int | None = None
        else:
            extracted_count = len(extracted_ids)
            relation_count_out = relation_count

        if self._audit is not None:
            self._audit.ingested(
                source_id=source_id,
                scope=scope,
                entity_count=len(entity_ids),
                actor=principal.user_id,
                extracted_entity_count=extracted_count,
                relation_count=relation_count_out,
            )
        logger.info(
            "ingested %d chunk(s) scope=%s source=%s actor=%s extracted=%s relations=%s",
            len(entity_ids),
            scope,
            source_id,
            principal.user_id,
            extracted_count,
            relation_count_out,
        )
        return IngestionResult(
            entity_ids=tuple(entity_ids),
            chunk_count=len(entity_ids),
            scope=scope,
            source_id=source_id,
            extracted_entity_count=extracted_count,
            relation_count=relation_count_out,
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

    def _enrich_with_extraction(
        self,
        *,
        document: IngestDocument,
        scope: Scope,
        acl: tuple[str, ...],
        owner_segment: str,
        source_id: str,
        chunk_entity_ids: list[str],
    ) -> tuple[tuple[str, ...], int]:
        """Write LLM-extracted typed entities + relations; return ``(entity_ids, relation_count)``.

        Security-critical: ``scope`` and ``acl`` are the server-resolved values from
        :meth:`_resolve_scope_acl` and are applied verbatim — the extractor's output decides only
        *which* nodes/edges exist, never *who can read them*. Extraction is an enrichment: any failure
        degrades to chunks-only (the core write already happened) and is logged by exception *type*
        only (never the document content).
        """
        if self._extractor is None:
            return (), 0
        # The degrade guard spans BOTH the model call and the persistence of its output: a transient
        # store error (pool exhaustion, deadlock, ...) while upserting an extracted entity or writing
        # a relation must not propagate out of ``ingest`` and break the already-committed core chunks.
        try:
            result = self._extractor.extract(document.text)
            return self._persist_extraction(
                result=result,
                scope=scope,
                acl=acl,
                owner_segment=owner_segment,
                source_id=source_id,
                chunk_entity_ids=chunk_entity_ids,
            )
        except Exception as exc:  # noqa: BLE001 — degrade gracefully; never fail the core write.
            logger.warning(
                "entity extraction failed (%s); persisted chunks only for source=%s",
                type(exc).__name__,
                source_id,
            )
            return (), 0

    def _persist_extraction(
        self,
        *,
        result: ExtractionResult,
        scope: Scope,
        acl: tuple[str, ...],
        owner_segment: str,
        source_id: str,
        chunk_entity_ids: list[str],
    ) -> tuple[tuple[str, ...], int]:
        """Write the extractor's entities + relations to the KG; return ``(entity_ids, relations)``.

        Wrapped by :meth:`_enrich_with_extraction`'s degrade guard, so any store failure here yields
        chunks-only. ``scope``/``acl`` are server-resolved and applied verbatim (never from the model).
        """
        # Map proposed entities -> KG entities with deterministic, idempotent ids. Dedup by
        # (kind, normalized name) so the same concept never produces two nodes.
        entity_id_by_key: dict[tuple[str, str], str] = {}
        extracted_ids: list[str] = []
        entities: list[Entity] = []
        for proposed in result.entities:
            if len(extracted_ids) >= self._max_extracted_entities:
                break
            key = (proposed.type, _normalize_name(proposed.name))
            if key in entity_id_by_key:
                continue
            entity_id = _extracted_entity_id(owner_segment, source_id, proposed.type, key[1])
            entities.append(
                Entity(
                    id=entity_id,
                    type=proposed.type,
                    name=proposed.name,
                    content="",
                    acl=acl,  # server-resolved — never from the model
                    scope=scope,  # server-resolved — never from the model
                )
            )
            entity_id_by_key[key] = entity_id
            extracted_ids.append(entity_id)

        relations = self._collect_relations(
            relations=result.relations,
            entity_id_by_key=entity_id_by_key,
            extracted_ids=extracted_ids,
            chunk_entity_ids=chunk_entity_ids,
        )
        self._knowledge.persist_extraction(
            owner_segment=owner_segment,
            source_id=source_id,
            entities=entities,
            relations=relations,
        )
        return tuple(extracted_ids), len(relations)

    def _collect_relations(
        self,
        *,
        relations: tuple[ExtractedRelation, ...],
        entity_id_by_key: dict[tuple[str, str], str],
        extracted_ids: list[str],
        chunk_entity_ids: list[str],
    ) -> list[Relation]:
        """Collect inter-entity relations then doc->concept ``mentions`` edges, within the cap.

        Inter-entity relations are collected first (higher value) so the cap never starves them in
        favor of mentions. A relation is dropped (fail-closed) unless *both* endpoints resolve to an
        entity we actually extracted — hallucinated/dangling edges are never persisted.
        """
        seen: set[tuple[str, str, str]] = set()
        collected: list[Relation] = []
        for relation in relations:
            if len(collected) >= self._max_extracted_relations:
                break
            src_id = entity_id_by_key.get((relation.src_type, _normalize_name(relation.src_name)))
            dst_id = entity_id_by_key.get((relation.dst_type, _normalize_name(relation.dst_name)))
            if src_id is None or dst_id is None:
                continue  # dangling/hallucinated edge — drop it
            edge = (src_id, dst_id, relation.type)
            if edge in seen:
                continue
            collected.append(Relation(src_id=src_id, dst_id=dst_id, type=relation.type))
            seen.add(edge)

        # Anchor each concept back to the document via a ``mentions`` edge from the first chunk
        # (always present — ``chunks`` is non-empty by the time we get here).
        doc_anchor = chunk_entity_ids[0]
        for entity_id in extracted_ids:
            if len(collected) >= self._max_extracted_relations:
                break
            edge = (doc_anchor, entity_id, MENTIONS_RELATION)
            if edge in seen:
                continue
            collected.append(Relation(src_id=doc_anchor, dst_id=entity_id, type=MENTIONS_RELATION))
            seen.add(edge)
        return collected


def _normalize_name(name: str) -> str:
    """Case/space-fold a name for dedup keys (so 'Acme Corp' and 'acme  corp' collapse)."""
    return " ".join(name.split()).casefold()


def _extracted_entity_id(
    owner_segment: str, source_id: str, kind: str, normalized_name: str
) -> str:
    """A deterministic, collision-resistant id for an extracted entity (idempotent re-ingest).

    Namespaced by ``owner_segment`` (PKG isolation) + ``source_id``; the kind+name is hashed so two
    distinct names can never collapse to the same node, and re-extracting the same concept upserts.
    """
    digest = hashlib.sha256(f"{kind}\x00{normalized_name}".encode("utf-8")).hexdigest()[:12]
    return f"{owner_segment}:{source_id}:entity:{kind}:{digest}"
