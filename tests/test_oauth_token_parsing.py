"""OAuth token parsing and refresh unit tests (M4.3 bug fixes)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from pydantic import SecretStr

from atlas.integrations.oauth import (
    GOOGLE_GMAIL_SEND,
    GoogleOAuthClient,
    SlackOAuthClient,
    _stored_from_slack_token,
)


def test_stored_from_slack_token_reads_top_level_rotation_fields() -> None:
    token = {
        "ok": True,
        "access_token": "new-access",
        "refresh_token": "new-refresh",
        "expires_in": 43200,
        "authed_user": {"id": "U1"},
    }
    cred = _stored_from_slack_token(token)
    assert cred.access_token == "new-access"
    assert cred.refresh_token == "new-refresh"
    assert cred.expires_at is not None
    assert cred.expires_at > datetime.now(UTC)


def test_stored_from_slack_token_prefers_authed_user_fields_on_connect() -> None:
    token = {
        "ok": True,
        "access_token": "bot-token",
        "refresh_token": "bot-refresh",
        "expires_in": 3600,
        "authed_user": {
            "id": "U1",
            "access_token": "user-access",
            "refresh_token": "user-refresh",
            "expires_in": 43200,
        },
    }
    cred = _stored_from_slack_token(token)
    assert cred.access_token == "user-access"
    assert cred.refresh_token == "user-refresh"


def test_slack_refresh_preserves_prior_refresh_token_when_omitted() -> None:
    client = SlackOAuthClient("cid", SecretStr("secret"), "http://localhost/cb")
    with patch("atlas.integrations.oauth.OAuth2Client") as mock_oauth2:
        instance = MagicMock()
        instance.refresh_token.return_value = {
            "ok": True,
            "access_token": "rotated",
            "expires_in": 43200,
            "authed_user": {"id": "U1"},
        }
        mock_oauth2.return_value = instance
        cred = client.refresh("old-refresh")
    assert cred.access_token == "rotated"
    assert cred.refresh_token == "old-refresh"


def test_google_refresh_preserves_prior_scopes_when_scope_omitted() -> None:
    client = GoogleOAuthClient("gid", SecretStr("secret"), "http://localhost/cb")
    with patch("atlas.integrations.oauth.OAuth2Client") as mock_oauth2:
        instance = MagicMock()
        instance.refresh_token.return_value = {
            "access_token": "new-access",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_oauth2.return_value = instance
        cred = client.refresh("rt", prior_scopes=(GOOGLE_GMAIL_SEND,))
    assert cred.access_token == "new-access"
    assert cred.scopes == (GOOGLE_GMAIL_SEND,)
    assert cred.refresh_token == "rt"
