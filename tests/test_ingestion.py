"""Knowledge ingestion — the KG write path (M4.4), offline/hermetic.

Covers deterministic chunking, idempotent dedup, per-user PKG isolation (the identity ACL), the
fail-closed OKG write gate, and the content-agnostic audit event. Mirrors the AAA style used across
``tests/`` and injects in-memory collaborators (no network, no Postgres).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore, Principal
from atlas.knowledge import (
    IngestDocument,
    IngestionDenied,
    IngestionService,
    InMemoryKnowledgeGraph,
    chunk_text,
)

ALICE = Principal(user_id="alice", roles=("member",))
BOB = Principal(user_id="bob", roles=("member",))
ADMIN = Principal(user_id="root", roles=("admin",))


def _service(
    audit: InMemoryAuditLog | None = None,
) -> tuple[IngestionService, InMemoryKnowledgeGraph]:
    kg = InMemoryKnowledgeGraph()
    return IngestionService(kg, InMemoryPolicyStore(), audit), kg


# --- chunk_text (pure, deterministic) ----------------------------------------
def test_chunk_text_returns_single_chunk_when_text_fits() -> None:
    assert chunk_text("short note", chunk_size=100, overlap=10) == ["short note"]


def test_chunk_text_splits_long_text_with_overlap() -> None:
    text = "abcdefghij" * 3  # 30 chars
    chunks = chunk_text(text, chunk_size=10, overlap=2)
    assert len(chunks) > 1
    assert all(len(chunk) <= 10 for chunk in chunks)


def test_chunk_text_is_deterministic() -> None:
    text = "deterministic " * 50
    assert chunk_text(text, chunk_size=64, overlap=8) == chunk_text(text, chunk_size=64, overlap=8)


def test_chunk_text_empty_or_whitespace_yields_no_chunks() -> None:
    assert chunk_text("   \n  ") == []


def test_chunk_text_rejects_invalid_overlap() -> None:
    with pytest.raises(ValueError):
        chunk_text("x", chunk_size=10, overlap=10)


def test_ingest_document_rejects_whitespace_only_text() -> None:
    with pytest.raises(ValidationError):
        IngestDocument(text="   ", title="t")


def test_whitespace_only_ingest_denied_after_prior_real_content() -> None:
    audit = InMemoryAuditLog()
    service, kg = _service(audit)
    document = IngestDocument(text="real content here", title="memo", source_id="src-1")
    first = service.ingest(ALICE, document)
    assert first.chunk_count == 1

    with pytest.raises(ValidationError):
        IngestDocument(text="   ", title="memo", source_id="src-1")

    assert len(kg.query(ALICE, "real", limit=10)) == 1
    assert len(audit.events()) == 1
    assert audit.events()[0].detail == {"scope": "personal", "entity_count": 1}


# --- ingest: chunking → entities ---------------------------------------------
def test_short_doc_becomes_one_entity() -> None:
    service, kg = _service()
    result = service.ingest(ALICE, IngestDocument(text="hello world", title="greeting"))
    assert result.chunk_count == 1
    assert len(kg.query(ALICE, "hello")) == 1


def test_long_doc_becomes_multiple_entities() -> None:
    service, kg = _service()
    long_text = "paragraph " * 1000  # well over the default chunk size
    result = service.ingest(ALICE, IngestDocument(text=long_text, title="big"))
    assert result.chunk_count > 1
    assert len(result.entity_ids) == result.chunk_count


# --- idempotency / dedup -----------------------------------------------------
def test_reingest_is_idempotent_no_duplicate_growth() -> None:
    service, kg = _service()
    document = IngestDocument(text="same content", title="dup")

    first = service.ingest(ALICE, document)
    second = service.ingest(ALICE, document)

    assert first.entity_ids == second.entity_ids
    assert len(kg.query(ALICE, "", limit=1000)) == len(first.entity_ids)


# --- PKG isolation (identity ACL) --------------------------------------------
def test_personal_entity_has_identity_acl() -> None:
    service, kg = _service()
    service.ingest(ALICE, IngestDocument(text="alice secret", title="s", scope="personal"))
    entity = kg.query(ALICE, "secret")[0]
    assert entity.acl == ("kg:read:user:alice",)
    assert entity.scope == "personal"


def test_personal_entity_invisible_to_other_user() -> None:
    service, kg = _service()
    service.ingest(ALICE, IngestDocument(text="alice secret", title="s", scope="personal"))
    assert kg.query(ALICE, "secret")  # owner sees it
    assert kg.query(BOB, "secret") == []  # IDOR guard: another user does not


def test_two_users_same_title_do_not_collide() -> None:
    service, kg = _service()
    doc = IngestDocument(text="my notes", title="notes", scope="personal")
    alice_result = service.ingest(ALICE, doc)
    bob_result = service.ingest(BOB, doc)
    assert set(alice_result.entity_ids).isdisjoint(bob_result.entity_ids)
    assert {e.id for e in kg.query(ALICE, "notes")} == set(alice_result.entity_ids)
    assert {e.id for e in kg.query(BOB, "notes")} == set(bob_result.entity_ids)


# --- OKG write gate (fail-closed) --------------------------------------------
def test_org_write_denied_without_permission_writes_nothing() -> None:
    service, kg = _service()
    with pytest.raises(IngestionDenied):
        service.ingest(ALICE, IngestDocument(text="org policy", title="p", scope="org"))
    assert kg.query(ADMIN, "", limit=1000) == []  # nothing persisted


def test_org_write_allowed_for_admin_and_org_readable() -> None:
    service, kg = _service()
    result = service.ingest(ADMIN, IngestDocument(text="org policy", title="p", scope="org"))
    assert result.scope == "org"
    entity = kg.query(ADMIN, "policy")[0]
    assert entity.acl == ("kg:read:org",)
    assert kg.query(ALICE, "policy")  # a member with kg:read:org can read it


def test_anonymous_principal_denied() -> None:
    service, _ = _service()
    with pytest.raises(IngestionDenied):
        service.ingest(Principal.anonymous(), IngestDocument(text="x", title="t"))
    with pytest.raises(IngestionDenied):
        service.ingest(None, IngestDocument(text="x", title="t"))


def test_org_acl_on_personal_scope_is_ambiguous_and_denied() -> None:
    service, _ = _service()
    with pytest.raises(IngestionDenied):
        service.ingest(
            ALICE,
            IngestDocument(text="x", title="t", scope="personal", org_acl=("kg:read:org",)),
        )


# --- audit (content-agnostic) ------------------------------------------------
def test_ingest_records_content_free_audit_event() -> None:
    audit = InMemoryAuditLog()
    service, _ = _service(audit)
    service.ingest(ALICE, IngestDocument(text="confidential body text", title="memo"))

    events = audit.events()
    assert [e.event_type.value for e in events] == ["ingested"]
    event = events[0]
    assert event.actor == "alice"
    assert event.detail == {"scope": "personal", "entity_count": 1}
    # The document body must never appear anywhere in the audit trail.
    assert "confidential body text" not in str(event.model_dump())
