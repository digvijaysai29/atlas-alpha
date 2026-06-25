"""OAuth HTTP route tests (M4.3)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from atlas.config import Settings
from atlas.governance.credentials import InMemoryCredentialVault, OAuthProvider, StoredCredential
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.oauth_state import issue_oauth_state
from atlas.integrations.oauth import GOOGLE_GMAIL_SEND
from atlas.orchestration import build_graph
from tests.helpers import offline_registry

_MEMBER = Principal(user_id="alice", roles=("member",), org_id="acme")
_HEADERS = {
    "X-Atlas-User-Id": "alice",
    "X-Atlas-Roles": "member",
    "X-Atlas-Org": "acme",
}


@pytest.fixture
def oauth_client() -> TestClient:
    vault = InMemoryCredentialVault()
    atlas = build_graph(registry=offline_registry())
    app = create_app(
        atlas=atlas,
        settings=Settings(
            ANTHROPIC_API_KEY=None,
            GOOGLE_OAUTH_CLIENT_ID="gid",
            GOOGLE_OAUTH_CLIENT_SECRET="gsecret",
            GOOGLE_OAUTH_REDIRECT_URI="http://localhost/oauth/google/callback",
        ),
    )
    app.state.credential_vault = vault
    return TestClient(app)


def test_list_connections_empty(oauth_client: TestClient) -> None:
    resp = oauth_client.get("/oauth/connections", headers=_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["providers"] == []


def test_list_connections_shows_connected(oauth_client: TestClient) -> None:
    vault: InMemoryCredentialVault = oauth_client.app.state.credential_vault
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


def test_callback_stores_credential(
    oauth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = oauth_client.app.state.settings
    state = issue_oauth_state(settings, _MEMBER, OAuthProvider.GOOGLE)
    mock_client = MagicMock()
    mock_client.exchange_code.return_value = StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=(GOOGLE_GMAIL_SEND,),
        access_token="stored",
    )
    monkeypatch.setattr(
        "atlas.interface.oauth_routes.build_google_oauth_client",
        lambda _settings: mock_client,
    )
    resp = oauth_client.get(
        f"/oauth/google/callback?code=abc&state={state}",
        headers=_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    vault: InMemoryCredentialVault = oauth_client.app.state.credential_vault
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "stored"


def test_revoke_deletes_credential(oauth_client: TestClient) -> None:
    vault: InMemoryCredentialVault = oauth_client.app.state.credential_vault
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
