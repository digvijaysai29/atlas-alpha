"""OIDC / JWT bearer-auth tests (offline, hermetic).

An in-test RSA keypair signs JWTs; the authenticator verifies against the local public key via an
injected ``get_signing_key`` — no network, no real provider. Covers happy-path claim mapping, every
fail-closed rejection (→ 401), and that the M3.2 owner-binding still holds under verified identity.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.auth import OidcAuthenticator, _parse_roles, build_authenticator
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry

from fastapi.testclient import TestClient

ISSUER = "https://issuer.test/"
AUDIENCE = "atlas-api"


@pytest.fixture(scope="module")
def keypair() -> tuple[RSAPrivateKey, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _authenticator(public_key: Any) -> OidcAuthenticator:
    return OidcAuthenticator(
        issuer=ISSUER, audience=AUDIENCE, get_signing_key=lambda _token: public_key
    )


def _client(public_key: Any, plan_fn: PlanFn = _send_plan) -> tuple[TestClient, Atlas]:
    atlas = build_graph(plan_fn=plan_fn, checkpointer=InMemorySaver(serde=atlas_serde()))
    app = create_app(
        atlas=atlas,
        settings=Settings(ANTHROPIC_API_KEY=None),
        authenticator=_authenticator(public_key),
    )
    return TestClient(app), atlas


def _token(
    private_key: RSAPrivateKey,
    *,
    sub: str = "alice",
    roles: Any = ("member",),
    org: str | None = None,
    aud: str = AUDIENCE,
    iss: str = ISSUER,
    exp_delta: int = 3600,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_delta,
    }
    if roles is not None:
        payload["roles"] = roles if isinstance(roles, str) else list(roles)
    if org is not None:
        payload["org_id"] = org
    return jwt.encode(payload, private_key, algorithm="RS256")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- happy path --------------------------------------------------------------
def test_valid_token_authenticates_and_authorizes(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    resp = client.post("/chat", json={"message": "email"}, headers=_bearer(_token(priv)))
    assert resp.status_code == 200
    assert resp.json()["status"] == "awaiting_approval"  # member may send => gated


@pytest.mark.parametrize("roles", [["member"], "member", "member, guest", "member guest"])
def test_roles_claim_parses_list_and_string(keypair: tuple[RSAPrivateKey, Any], roles: Any) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    resp = client.post(
        "/chat", json={"message": "email"}, headers=_bearer(_token(priv, roles=roles))
    )
    assert resp.json()["status"] == "awaiting_approval"


def test_healthz_is_public(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    client, _ = _client(pub)
    assert client.get("/healthz").json() == {"ok": True}


# --- fail-closed rejections (401) -------------------------------------------
def test_missing_token_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    client, _ = _client(pub)
    resp = client.post("/chat", json={"message": "email"})
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate") == "Bearer"
    assert resp.json()["ok"] is False


def test_non_bearer_scheme_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    resp = client.post(
        "/chat", json={"message": "email"}, headers={"Authorization": f"Basic {_token(priv)}"}
    )
    assert resp.status_code == 401


def test_expired_token_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    token = _token(priv, exp_delta=-3600)
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(token)).status_code == 401


def test_wrong_audience_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    token = _token(priv, aud="someone-else")
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(token)).status_code == 401


def test_wrong_issuer_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    token = _token(priv, iss="https://evil.test/")
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(token)).status_code == 401


def test_bad_signature_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _ = _client(pub)  # verifies against `pub`
    token = _token(other_key)  # but signed with a different key
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(token)).status_code == 401


def test_alg_none_token_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    client, _ = _client(pub)
    now = int(time.time())
    unsigned = jwt.encode(
        {"sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": now + 3600},
        key="",
        algorithm="none",
    )
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(unsigned)).status_code == 401


def test_hs256_forgery_is_401(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    client, _ = _client(pub)
    now = int(time.time())
    forged = jwt.encode(
        {"sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": now + 3600},
        "shared-secret-shared-secret-0123456789",  # ≥32 bytes to avoid a length warning
        algorithm="HS256",
    )
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(forged)).status_code == 401


def test_anonymous_subject_is_rejected(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    token = _token(priv, sub="anonymous")
    assert client.post("/chat", json={"message": "x"}, headers=_bearer(token)).status_code == 401


def test_header_shim_is_ignored_when_oidc_enabled(keypair: tuple[RSAPrivateKey, Any]) -> None:
    _, pub = keypair
    client, _ = _client(pub)
    # Supplying the dev header but no bearer token must NOT authenticate under OIDC mode.
    resp = client.post(
        "/chat",
        json={"message": "email"},
        headers={"X-Atlas-User-Id": "alice", "X-Atlas-Roles": "member"},
    )
    assert resp.status_code == 401


# --- owner-binding still holds under OIDC ------------------------------------
def test_owner_binding_under_oidc(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    tid = client.post(
        "/chat", json={"message": "email"}, headers=_bearer(_token(priv, sub="alice"))
    ).json()["thread_id"]
    # Bob (valid token, different subject) cannot approve Alice's thread.
    bob = client.post(
        "/approve",
        json={"thread_id": tid, "approve": True},
        headers=_bearer(_token(priv, sub="bob")),
    )
    assert bob.status_code == 403
    # Alice resumes and the action executes.
    alice = client.post(
        "/approve",
        json={"thread_id": tid, "approve": True},
        headers=_bearer(_token(priv, sub="alice")),
    ).json()
    assert alice["action_results"][0]["ok"] is True


def test_org_claim_participates_in_owner_binding(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    client, _ = _client(pub)
    tid = client.post(
        "/chat", json={"message": "email"}, headers=_bearer(_token(priv, sub="alice", org="acme"))
    ).json()["thread_id"]
    # Same user_id but a different org must not match the thread owner.
    other_org = client.get(
        f"/threads/{tid}", headers=_bearer(_token(priv, sub="alice", org="evil"))
    )
    assert other_org.status_code == 403
    same_org = client.get(f"/threads/{tid}", headers=_bearer(_token(priv, sub="alice", org="acme")))
    assert same_org.status_code == 200


def test_whitespace_org_claim_matches_missing_org_in_owner_binding(
    keypair: tuple[RSAPrivateKey, Any],
) -> None:
    """Whitespace-only org_id claims normalize to None — must not 403 vs a no-org thread owner."""
    priv, pub = keypair
    client, _ = _client(pub)
    tid = client.post(
        "/chat", json={"message": "email"}, headers=_bearer(_token(priv, sub="alice"))
    ).json()["thread_id"]
    resp = client.get(f"/threads/{tid}", headers=_bearer(_token(priv, sub="alice", org="   ")))
    assert resp.status_code == 200


# --- unit: claim parsing -----------------------------------------------------
def test_parse_roles_is_defensive() -> None:
    assert _parse_roles(None) == ()
    assert _parse_roles("") == ()
    assert _parse_roles("   ") == ()
    assert _parse_roles("member, admin") == ("member", "admin")
    assert _parse_roles("member admin") == ("member", "admin")
    assert _parse_roles(["member", " admin ", ""]) == ("member", "admin")
    assert _parse_roles(123) == ()


def test_principal_from_token_maps_claims(keypair: tuple[RSAPrivateKey, Any]) -> None:
    priv, pub = keypair
    auth = _authenticator(pub)
    principal = auth.principal_from_token(_token(priv, sub="alice", roles=["member"], org="acme"))
    assert principal == Principal(user_id="alice", roles=("member",), org_id="acme")


@pytest.mark.parametrize("org", [None, "", "   "])
def test_principal_from_token_normalizes_blank_org_claim(
    keypair: tuple[RSAPrivateKey, Any], org: str | None
) -> None:
    priv, pub = keypair
    auth = _authenticator(pub)
    token_kwargs: dict[str, Any] = {"sub": "alice"}
    if org is not None:
        token_kwargs["org"] = org
    principal = auth.principal_from_token(_token(priv, **token_kwargs))
    assert principal.org_id is None


def test_build_authenticator_returns_none_in_dev_mode() -> None:
    assert build_authenticator(Settings(ANTHROPIC_API_KEY=None)) is None
