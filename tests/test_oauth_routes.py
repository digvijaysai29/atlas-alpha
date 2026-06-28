"""OAuth HTTP route tests (M4.3)."""

from __future__ import annotations

import time
from typing import Any, cast
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from atlas.config import Settings
from atlas.governance.credentials import InMemoryCredentialVault, OAuthProvider, StoredCredential
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.auth import OidcAuthenticator
from atlas.interface.oauth_pending import OAUTH_PENDING_COOKIE, sign_pending_nonce
from atlas.interface.oauth_state import consume_oauth_state, issue_oauth_state
from atlas.integrations.oauth import GOOGLE_GMAIL_SEND, OAuthExchangeResult
from atlas.integrations.oauth_binding import OAuthBindingError
from atlas.orchestration import build_graph
from tests.helpers import offline_registry

_MEMBER = Principal(user_id="alice", roles=("member",), org_id="acme")
_EMAIL = "alice@example.com"
_HEADERS = {
    "X-Atlas-User-Id": "alice",
    "X-Atlas-Roles": "member",
    "X-Atlas-Org": "acme",
    "X-Atlas-Email": _EMAIL,
}
_ISSUER = "https://issuer.test/"
_AUDIENCE = "atlas-api"


def _oauth_settings(**overrides: Any) -> Settings:
    base = {
        "ANTHROPIC_API_KEY": None,
        "GOOGLE_OAUTH_CLIENT_ID": "gid",
        "GOOGLE_OAUTH_CLIENT_SECRET": "gsecret",
        "GOOGLE_OAUTH_REDIRECT_URI": "http://localhost/oauth/google/callback",
        "ATLAS_OAUTH_ALLOW_INSECURE_STATE": True,
    }
    base.update(overrides)
    return Settings.model_validate(base)


def _fastapi_app(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def _google_exchange(access_token: str) -> OAuthExchangeResult:
    credential = StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=(GOOGLE_GMAIL_SEND,),
        access_token=access_token,
    )
    return OAuthExchangeResult(credential=credential, token_response={"id_token": "mock"})


def _passthrough_binding(*args: object, **kwargs: object) -> StoredCredential:
    return kwargs["credential"]  # type: ignore[return-value]


@pytest.fixture
def oauth_client() -> TestClient:
    vault = InMemoryCredentialVault()
    atlas = build_graph(registry=offline_registry())
    app = create_app(atlas=atlas, settings=_oauth_settings())
    app.state.credential_vault = vault
    return TestClient(app)


@pytest.fixture(scope="module")
def keypair() -> tuple[RSAPrivateKey, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _oidc_token(private_key: RSAPrivateKey, *, org: str = "acme") -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "alice",
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "org_id": org,
            "email": _EMAIL,
            "roles": ["member"],
            "exp": now + 3600,
        },
        private_key,
        algorithm="RS256",
    )


def _oidc_client(keypair: tuple[RSAPrivateKey, Any]) -> TestClient:
    private_key, public_key = keypair
    vault = InMemoryCredentialVault()
    atlas = build_graph(registry=offline_registry())
    authenticator = OidcAuthenticator(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        get_signing_key=lambda _token: public_key,
    )
    app = create_app(
        atlas=atlas,
        settings=_oauth_settings(
            ATLAS_OIDC_ISSUER=_ISSUER,
            ATLAS_OIDC_AUDIENCE=_AUDIENCE,
            ATLAS_OIDC_JWKS_URI="https://issuer.test/.well-known/jwks.json",
            ATLAS_OIDC_ALLOW_INSECURE_HTTP=True,
        ),
        authenticator=authenticator,
    )
    app.state.credential_vault = vault
    return TestClient(app)


def test_list_connections_empty(oauth_client: TestClient) -> None:
    resp = oauth_client.get("/oauth/connections", headers=_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["providers"] == []


def test_list_connections_shows_connected(oauth_client: TestClient) -> None:
    vault: InMemoryCredentialVault = _fastapi_app(oauth_client).state.credential_vault
    vault.put(
        _MEMBER,
        OAuthProvider.GOOGLE,
        StoredCredential(
            provider=OAuthProvider.GOOGLE,
            scopes=(GOOGLE_GMAIL_SEND,),
            access_token="tok",
        ),
    )
    resp = oauth_client.get("/oauth/connections", headers=_HEADERS)
    assert resp.json()["providers"] == ["google"]


def test_connect_redirects_to_google(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_client = MagicMock()
    mock_client.authorization_url.return_value = "https://accounts.google.com/o/oauth2/auth"
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    resp = oauth_client.get("/oauth/google/connect", headers=_HEADERS, follow_redirects=False)
    assert resp.status_code == 302
    assert "accounts.google.com" in resp.headers["location"]
    assert OAUTH_PENDING_COOKIE in resp.cookies


def test_connect_json_mode_returns_url_and_cookie(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_client = MagicMock()
    mock_client.authorization_url.return_value = "https://accounts.google.com/o/oauth2/auth"
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    resp = oauth_client.get(
        "/oauth/google/connect",
        headers={**_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    assert "accounts.google.com" in resp.json()["authorization_url"]
    assert OAUTH_PENDING_COOKIE in resp.cookies


def test_callback_stores_credential_with_headers(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _fastapi_app(oauth_client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("stored")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _passthrough_binding,
    )
    resp = oauth_client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        headers=_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    vault: InMemoryCredentialVault = _fastapi_app(oauth_client).state.credential_vault
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "stored"


def test_callback_with_pending_cookie_no_headers(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _fastapi_app(oauth_client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    payload = consume_oauth_state(settings, state)
    nonce = str(payload["nonce"])
    cookie = sign_pending_nonce(settings, nonce)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("cookie-stored")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _passthrough_binding,
    )
    resp = oauth_client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        cookies={OAUTH_PENDING_COOKIE: cookie},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    vault: InMemoryCredentialVault = _fastapi_app(oauth_client).state.credential_vault
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "cookie-stored"


def test_callback_without_auth_returns_401(oauth_client: TestClient) -> None:
    settings = _fastapi_app(oauth_client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    resp = oauth_client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        follow_redirects=False,
    )
    assert resp.status_code == 401


def test_post_callback_with_bearer_oidc(
    keypair: tuple[RSAPrivateKey, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _oidc_client(keypair)
    settings = _fastapi_app(client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("post-stored")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _passthrough_binding,
    )
    token = _oidc_token(keypair[0])
    resp = client.post(
        "/oauth/google/callback",
        json={"code": "abc", "state": state},
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    vault: InMemoryCredentialVault = _fastapi_app(client).state.credential_vault
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "post-stored"


def test_oidc_get_callback_with_pending_cookie_succeeds(
    keypair: tuple[RSAPrivateKey, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _oidc_client(keypair)
    settings = _fastapi_app(client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    payload = consume_oauth_state(settings, state)
    nonce = str(payload["nonce"])
    cookie = sign_pending_nonce(settings, nonce)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("oidc-cookie-stored")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _passthrough_binding,
    )
    resp = client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        cookies={OAUTH_PENDING_COOKIE: cookie},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    vault: InMemoryCredentialVault = _fastapi_app(client).state.credential_vault
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "oidc-cookie-stored"


def test_oidc_get_callback_without_cookie_or_bearer_returns_401(
    keypair: tuple[RSAPrivateKey, Any],
) -> None:
    client = _oidc_client(keypair)
    settings = _fastapi_app(client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    resp = client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        follow_redirects=False,
    )
    assert resp.status_code == 401


def test_revoke_deletes_credential(oauth_client: TestClient) -> None:
    vault: InMemoryCredentialVault = _fastapi_app(oauth_client).state.credential_vault
    vault.put(
        _MEMBER,
        OAuthProvider.GOOGLE,
        StoredCredential(
            provider=OAuthProvider.GOOGLE,
            scopes=(GOOGLE_GMAIL_SEND,),
            access_token="tok",
        ),
    )
    resp = oauth_client.delete("/oauth/google", headers=_HEADERS)
    assert resp.status_code == 200
    assert vault.get(_MEMBER, OAuthProvider.GOOGLE) is None


def test_connect_without_email_returns_400(oauth_client: TestClient) -> None:
    headers = {
        "X-Atlas-User-Id": "alice",
        "X-Atlas-Roles": "member",
        "X-Atlas-Org": "acme",
    }
    resp = oauth_client.get("/oauth/google/connect", headers=headers, follow_redirects=False)
    assert resp.status_code == 400
    assert "email" in resp.json()["error"]["message"].lower()


def test_callback_rejects_provider_email_mismatch(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _fastapi_app(oauth_client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("stolen")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )

    def _wrong_email(*args: object, **kwargs: object) -> StoredCredential:
        raise OAuthBindingError("provider account does not match connected Atlas user")

    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _wrong_email,
    )
    resp = oauth_client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        headers=_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 400
    vault: InMemoryCredentialVault = _fastapi_app(oauth_client).state.credential_vault
    assert vault.get(_MEMBER, OAuthProvider.GOOGLE) is None


def test_post_callback_rejects_cross_account_linking(
    keypair: tuple[RSAPrivateKey, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _oidc_client(keypair)
    settings = _fastapi_app(client).state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE, binding_email=_EMAIL)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = _google_exchange("victim-token")
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )

    def _wrong_email(*args: object, **kwargs: object) -> StoredCredential:
        raise OAuthBindingError("provider account does not match connected Atlas user")

    monkeypatch.setattr(
        "atlas.interface.oauth_routes.assert_provider_email_binding",
        _wrong_email,
    )
    token = _oidc_token(keypair[0])
    resp = client.post(
        "/oauth/google/callback",
        json={"code": "victim-code", "state": state},
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    vault: InMemoryCredentialVault = _fastapi_app(client).state.credential_vault
    assert vault.get(_MEMBER, OAuthProvider.GOOGLE) is None
