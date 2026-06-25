"""OAuth provider identity binding tests (M4.3 security)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from atlas.governance.credentials import OAuthProvider, StoredCredential
from atlas.integrations.oauth import GoogleOAuthClient, SLACK_IDENTITY_BASIC, SLACK_USER_CHAT_WRITE
from atlas.integrations.oauth_binding import (
    OAuthBindingError,
    assert_emails_match,
    assert_provider_email_binding,
    google_provider_email,
    normalize_email,
    require_binding_email,
    slack_provider_email,
)

_ALICE = "alice@example.com"
_BOB = "bob@example.com"


def test_normalize_email() -> None:
    assert normalize_email(" Alice@Example.COM ") == "alice@example.com"


def test_assert_emails_match_accepts_equal() -> None:
    assert_emails_match(expected=_ALICE, actual="ALICE@example.com")


def test_assert_emails_match_rejects_mismatch() -> None:
    with pytest.raises(OAuthBindingError, match="does not match"):
        assert_emails_match(expected=_ALICE, actual=_BOB)


def test_require_binding_email_from_state() -> None:
    assert require_binding_email({"binding_email": _ALICE}) == _ALICE


def test_require_binding_email_missing() -> None:
    with pytest.raises(OAuthBindingError, match="binding_email"):
        require_binding_email({})


def test_google_provider_email_verifies_id_token() -> None:
    client = GoogleOAuthClient("gid", SecretStr("secret"), "http://localhost/cb")
    with patch("atlas.integrations.oauth_binding.OAuth2Client") as mock_oauth2:
        instance = MagicMock()
        instance.parse_id_token.return_value = {"email": _ALICE, "sub": "google-sub-1"}
        mock_oauth2.return_value = instance
        email, metadata = google_provider_email(client, {"id_token": "jwt"})
    assert email == _ALICE
    assert metadata["google_sub"] == "google-sub-1"
    assert metadata["provider_email"] == _ALICE


def test_google_provider_email_missing_id_token() -> None:
    client = GoogleOAuthClient("gid", SecretStr("secret"), "http://localhost/cb")
    with pytest.raises(OAuthBindingError, match="missing id_token"):
        google_provider_email(client, {})


def test_slack_provider_email_fetches_identity() -> None:
    response = MagicMock()
    response.json.return_value = {
        "ok": True,
        "user": {"id": "U123", "email": _ALICE},
        "team": {"id": "T456"},
    }
    response.raise_for_status = MagicMock()
    with patch("atlas.integrations.oauth_binding.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = response
        email, metadata = slack_provider_email("xoxp-token")
    assert email == _ALICE
    assert metadata["user_id"] == "U123"
    assert metadata["team_id"] == "T456"


def test_assert_provider_email_binding_google_mismatch() -> None:
    client = GoogleOAuthClient("gid", SecretStr("secret"), "http://localhost/cb")
    credential = StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=("openid",),
        access_token="tok",
    )
    with patch(
        "atlas.integrations.oauth_binding.google_provider_email",
        return_value=(_BOB, {"provider_email": _BOB}),
    ):
        with pytest.raises(OAuthBindingError, match="does not match"):
            assert_provider_email_binding(
                OAuthProvider.GOOGLE,
                binding_email=_ALICE,
                credential=credential,
                token_response={"id_token": "jwt"},
                google_client=client,
            )


def test_slack_oauth_scopes_include_identity() -> None:
    from atlas.integrations.oauth import SLACK_OAUTH_SCOPES

    assert SLACK_USER_CHAT_WRITE in SLACK_OAUTH_SCOPES
    assert SLACK_IDENTITY_BASIC in SLACK_OAUTH_SCOPES
