"""OAuth provider ↔ Atlas identity binding (M4.3 security).

Embeds the caller's email in signed OAuth state at connect time and verifies the provider account
email matches before tokens are persisted to the vault.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx
from authlib.integrations.httpx_client import OAuth2Client

from atlas.config import Settings
from atlas.governance.credentials import OAuthProvider, StoredCredential
from atlas.interface.auth import AuthDependencyError, AuthError
from atlas.interface.security import _bearer_token
from atlas.integrations.oauth import GoogleOAuthClient

if TYPE_CHECKING:
    from fastapi import Request

    from atlas.interface.auth import OidcAuthenticator

_SLACK_USERS_INFO_URL = "https://slack.com/api/users.info"


class OAuthBindingError(ValueError):
    """Provider account does not match the Atlas user who initiated OAuth connect."""


def normalize_email(email: str) -> str:
    """Normalize an email address for comparison."""
    return email.strip().lower()


def resolve_binding_email(request: Request, settings: Settings) -> str:
    """Resolve the caller's binding email from OIDC bearer token or dev header shim."""
    authenticator: OidcAuthenticator | None = getattr(request.app.state, "authenticator", None)
    token = _bearer_token(request)

    if token is not None and authenticator is not None:
        try:
            email = authenticator.email_from_token(token)
        except AuthDependencyError as exc:
            raise OAuthBindingError("authentication service unavailable") from exc
        except AuthError as exc:
            raise OAuthBindingError("invalid or expired token") from exc
        if not email:
            raise OAuthBindingError("email claim required for OAuth connect")
        return normalize_email(email)

    raw = (request.headers.get(settings.api_email_header) or "").strip()
    if not raw:
        raise OAuthBindingError("email claim required for OAuth connect")
    return normalize_email(raw)


def require_binding_email(payload: dict[str, Any]) -> str:
    """Extract normalized binding_email from verified OAuth state."""
    raw = payload.get("binding_email")
    if not isinstance(raw, str) or not raw.strip():
        raise OAuthBindingError("state missing binding_email")
    return normalize_email(raw)


def assert_emails_match(*, expected: str, actual: str) -> None:
    if normalize_email(expected) != normalize_email(actual):
        raise OAuthBindingError("provider account does not match connected Atlas user")


def google_provider_email(
    client: GoogleOAuthClient, token_response: dict[str, Any]
) -> tuple[str, dict[str, str]]:
    """Verify Google id_token and return provider email + metadata."""
    if not token_response.get("id_token"):
        raise OAuthBindingError("Google OAuth response missing id_token")

    oauth2 = OAuth2Client(
        client_id=client.client_id,
        client_secret=client.client_secret.get_secret_value(),
        redirect_uri=client.redirect_uri,
    )
    try:
        claims = oauth2.parse_id_token(token_response, nonce=None)
    except Exception as exc:
        raise OAuthBindingError("invalid Google id_token") from exc

    email_raw = claims.get("email")
    if not email_raw:
        raise OAuthBindingError("Google id_token missing email claim")
    email = normalize_email(str(email_raw))

    metadata: dict[str, str] = {"provider_email": email}
    sub = claims.get("sub")
    if sub:
        metadata["google_sub"] = str(sub)
    return email, metadata


def slack_provider_email(access_token: str, *, user_id: str) -> tuple[str, dict[str, str]]:
    """Fetch Slack user email via users.info (requires users:read.email user scope)."""
    with httpx.Client(timeout=10.0) as http:
        resp = http.get(
            _SLACK_USERS_INFO_URL,
            params={"user": user_id},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        data = resp.json()

    if not data.get("ok"):
        raise OAuthBindingError(data.get("error", "Slack users.info lookup failed"))

    user = data.get("user") or {}
    profile = user.get("profile") or {}
    email_raw = profile.get("email")
    if not email_raw:
        raise OAuthBindingError("Slack user profile missing email")
    email = normalize_email(str(email_raw))

    metadata: dict[str, str] = {"provider_email": email}
    if user.get("id"):
        metadata["user_id"] = str(user["id"])
    team = data.get("team") or {}
    if team.get("id"):
        metadata["team_id"] = str(team["id"])
    return email, metadata


def assert_provider_email_binding(
    provider: OAuthProvider,
    *,
    binding_email: str,
    credential: StoredCredential,
    token_response: dict[str, Any],
    google_client: GoogleOAuthClient | None = None,
) -> StoredCredential:
    """Verify provider identity matches binding_email; return credential with binding metadata."""
    if provider is OAuthProvider.GOOGLE:
        if google_client is None:
            raise OAuthBindingError("Google OAuth client not configured")
        provider_email, metadata = google_provider_email(google_client, token_response)
    elif provider is OAuthProvider.SLACK:
        user_id = credential.metadata.get("user_id")
        if not user_id:
            authed_user = token_response.get("authed_user") or {}
            raw_id = authed_user.get("id")
            if raw_id:
                user_id = str(raw_id)
        if not user_id:
            raise OAuthBindingError("Slack OAuth response missing user id")
        provider_email, metadata = slack_provider_email(credential.access_token, user_id=user_id)
    else:
        raise OAuthBindingError(f"unsupported provider: {provider.value}")

    assert_emails_match(expected=binding_email, actual=provider_email)

    merged = {**credential.metadata, **metadata}
    return credential.model_copy(update={"metadata": merged})
