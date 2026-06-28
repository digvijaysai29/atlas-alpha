"""HTTP tests for ``POST /kg/ingest`` (M4.4), offline/hermetic via FastAPI TestClient.

Built with an injected hermetic ``Atlas`` (in-memory KG/policy/audit + a scripted plan) so no API
key, network, or Postgres is needed. Asserts the happy path plus the fail-closed boundaries: a
member cannot write org knowledge (403), missing fields are a 422, and an ingested personal doc is
visible to its owner through ``/chat`` but not to another user.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.interface import create_app
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry


def _search_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "onboarding"})]


def _build(plan_fn: PlanFn = _search_plan) -> tuple[TestClient, Atlas]:
    atlas = build_graph(
        plan_fn=plan_fn,
        registry=offline_registry(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    app = create_app(atlas=atlas, settings=Settings(ANTHROPIC_API_KEY=None))
    return TestClient(app), atlas


def _headers(user: str, roles: str = "member") -> dict[str, str]:
    return {"X-Atlas-User-Id": user, "X-Atlas-Roles": roles}


def test_ingest_personal_happy_path() -> None:
    client, _ = _build()
    resp = client.post(
        "/kg/ingest",
        json={"text": "alice onboarding plan", "title": "plan", "scope": "personal"},
        headers=_headers("alice"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["scope"] == "personal"
    assert body["chunk_count"] == 1
    assert body["entity_ids"]


def test_ingest_org_denied_for_member() -> None:
    client, _ = _build()
    resp = client.post(
        "/kg/ingest",
        json={"text": "org wide policy", "title": "policy", "scope": "org"},
        headers=_headers("alice"),
    )
    assert resp.status_code == 403
    assert resp.json()["ok"] is False


def test_ingest_org_allowed_for_admin() -> None:
    client, _ = _build()
    resp = client.post(
        "/kg/ingest",
        json={"text": "org wide policy", "title": "policy", "scope": "org"},
        headers=_headers("root", roles="admin"),
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "org"


def test_ingest_validation_error_on_missing_text() -> None:
    client, _ = _build()
    resp = client.post("/kg/ingest", json={"title": "no text"}, headers=_headers("alice"))
    assert resp.status_code == 422


def test_ingest_validation_error_on_whitespace_only_text() -> None:
    client, _ = _build()
    resp = client.post(
        "/kg/ingest",
        json={"text": "   ", "title": "blank"},
        headers=_headers("alice"),
    )
    assert resp.status_code == 422


def test_whitespace_only_ingest_leaves_prior_entities_and_audit_unchanged() -> None:
    client, atlas = _build()
    first = client.post(
        "/kg/ingest",
        json={"text": "alice onboarding plan", "title": "plan", "scope": "personal"},
        headers=_headers("alice"),
    )
    assert first.status_code == 200
    entity_ids = first.json()["entity_ids"]
    audit_count_before = len(atlas.audit.events())

    second = client.post(
        "/kg/ingest",
        json={"text": "   ", "title": "plan", "scope": "personal"},
        headers=_headers("alice"),
    )
    assert second.status_code == 422
    assert len(atlas.audit.events()) == audit_count_before

    still_there = client.post(
        "/chat", json={"message": "onboarding"}, headers=_headers("alice")
    ).json()
    refs = {s.get("ref") for s in still_there.get("sources", [])}
    assert any(ref in entity_ids for ref in refs)


def test_ingested_personal_doc_is_owner_scoped_through_chat() -> None:
    # Ingest as alice, then prove the planner's RBAC-scoped retrieval surfaces it for alice (cited as
    # a knowledge source) but never for bob — end-to-end PKG isolation through the HTTP layer.
    client, _ = _build()
    client.post(
        "/kg/ingest",
        json={"text": "alice quarterly onboarding notes", "title": "notes", "scope": "personal"},
        headers=_headers("alice"),
    )

    alice_chat = client.post(
        "/chat", json={"message": "onboarding"}, headers=_headers("alice")
    ).json()
    bob_chat = client.post("/chat", json={"message": "onboarding"}, headers=_headers("bob")).json()

    alice_refs = {s.get("ref") for s in alice_chat.get("sources", [])}
    bob_refs = {s.get("ref") for s in bob_chat.get("sources", [])}
    assert any(ref and ref.startswith("personal:alice:") for ref in alice_refs)
    assert not any(ref and ref.startswith("personal:alice:") for ref in bob_refs)
