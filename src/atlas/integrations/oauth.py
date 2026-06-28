"""Outbound OAuth clients for Google and Slack (M4.3).

Authlib handles authorization-code exchange and token refresh; resulting tokens are stored in the
credential vault by the HTTP callback handler — never logged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from authlib.integrations.httpx_client import OAuth2Client
from pydantic import BaseModel, ConfigDict, SecretStr

from atlas.config import Settings
from atlas.governance.credentials import OAuthProvider, StoredCredential

# Google scopes (space-delimited in authorize URL).
GOOGLE_OPENID = "openid"
GOOGLE_EMAIL = "email"
GOOGLE_GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
GOOGLE_CALENDAR_EVENTS = "https://www.googleapis.com/auth/calendar.events"
GOOGLE_OAUTH_SCOPES = (
    GOOGLE_OPENID,
    GOOGLE_EMAIL,
    GOOGLE_GMAIL_SEND,
    GOOGLE_CALENDAR_EVENTS,
)

SLACK_USER_CHAT_WRITE = "chat:write"
SLACK_IDENTITY_BASIC = "identity.basic"
SLACK_OAUTH_SCOPES = (SLACK_USER_CHAT_WRITE, SLACK_IDENTITY_BASIC)

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_OAUTH_API = "https://oauth2.googleapis.com"
_GOOGLE_ACCESS_URL = f"{_GOOGLE_OAUTH_API}/token"
_SLACK_AUTH_URL = "https://slack.com/oauth/v2/authorize"
_SLACK_OAUTH_API = "https://slack.com/api"
_SLACK_ACCESS_URL = f"{_SLACK_OAUTH_API}/oauth.v2.access"


class OAuthExchangeResult(BaseModel):
    """Authorization-code exchange output for callback binding checks."""

    model_config = ConfigDict(frozen=True)

    credential: StoredCredential
    token_response: dict[str, Any]


def _expires_at_from_token(token: dict[str, Any]) -> datetime | None:
    expires_in = token.get("expires_in")
    if expires_in is None:
        return None
    return datetime.now(UTC) + timedelta(seconds=int(expires_in))


def _stored_from_google_token(token: dict[str, Any]) -> StoredCredential:
    scope_raw = token.get("scope") or ""
    scopes = tuple(s for s in scope_raw.split() if s)
    return StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=scopes,
        access_token=str(token["access_token"]),
        refresh_token=token.get("refresh_token"),
        expires_at=_expires_at_from_token(token),
        token_type=str(token.get("token_type") or "Bearer"),
        metadata={},
    )


def _stored_from_slack_token(token: dict[str, Any]) -> StoredCredential:
    authed_user = token.get("authed_user") or {}
    access = authed_user.get("access_token") or token.get("access_token")
    if not access:
        raise RuntimeError("Slack OAuth response missing user access token")
    metadata: dict[str, str] = {}
    team = token.get("team") or {}
    if team.get("id"):
        metadata["team_id"] = str(team["id"])
    if authed_user.get("id"):
        metadata["user_id"] = str(authed_user["id"])
    return StoredCredential(
        provider=OAuthProvider.SLACK,
        scopes=SLACK_OAUTH_SCOPES,
        access_token=str(access),
        refresh_token=authed_user.get("refresh_token"),
        expires_at=_expires_at_from_token(authed_user),
        metadata=metadata,
    )


class GoogleOAuthClient:
    """Google OAuth2 authorization-code + refresh."""

    def __init__(self, client_id: str, client_secret: SecretStr, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def client_secret(self) -> SecretStr:
        return self._client_secret

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    def authorization_url(self, state: str, *, scopes: tuple[str, ...] | None = None) -> str:
        scope_list = scopes or GOOGLE_OAUTH_SCOPES
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
            scope=" ".join(scope_list),
        )
        uri, _ = client.create_authorization_url(
            _GOOGLE_AUTH_URL,
            state=state,
            access_type="offline",
            prompt="consent",
        )
        return str(uri)

    def exchange_code(self, code: str) -> OAuthExchangeResult:
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
        )
        token = client.fetch_token(_GOOGLE_ACCESS_URL, code=code)
        return OAuthExchangeResult(
            credential=_stored_from_google_token(token),
            token_response=dict(token),
        )

    def refresh(self, refresh_token: str) -> StoredCredential:
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
        )
        token = client.refresh_token(_GOOGLE_ACCESS_URL, refresh_token=refresh_token)
        if token.get("refresh_token") is None:
            token["refresh_token"] = refresh_token
        return _stored_from_google_token(token)


class SlackOAuthClient:
    """Slack user OAuth v2 authorization-code + refresh."""

    def __init__(self, client_id: str, client_secret: SecretStr, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    def authorization_url(self, state: str) -> str:
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
            scope=",".join(SLACK_OAUTH_SCOPES),
        )
        uri, _ = client.create_authorization_url(
            _SLACK_AUTH_URL,
            state=state,
            user_scope=",".join(SLACK_OAUTH_SCOPES),
        )
        return str(uri)

    def exchange_code(self, code: str) -> OAuthExchangeResult:
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
        )
        token = client.fetch_token(_SLACK_ACCESS_URL, code=code)
        if not token.get("ok", True):
            raise RuntimeError(token.get("error", "Slack OAuth failed"))
        return OAuthExchangeResult(
            credential=_stored_from_slack_token(token),
            token_response=dict(token),
        )

    def refresh(self, refresh_token: str) -> StoredCredential:
        client = OAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret.get_secret_value(),
            redirect_uri=self._redirect_uri,
        )
        token = client.refresh_token(_SLACK_ACCESS_URL, refresh_token=refresh_token)
        if not token.get("ok", True):
            raise RuntimeError(token.get("error", "Slack token refresh failed"))
        return _stored_from_slack_token(token)


def build_google_oauth_client(settings: Settings) -> GoogleOAuthClient | None:
    if not settings.oauth_google_configured:
        return None
    cid = settings.google_oauth_client_id
    secret = settings.google_oauth_client_secret
    redirect = settings.google_oauth_redirect_uri
    if cid is None or secret is None or redirect is None:
        return None
    return GoogleOAuthClient(cid, secret, redirect)


def build_slack_oauth_client(settings: Settings) -> SlackOAuthClient | None:
    if not settings.oauth_slack_configured:
        return None
    cid = settings.slack_oauth_client_id
    secret = settings.slack_oauth_client_secret
    redirect = settings.slack_oauth_redirect_uri
    if cid is None or secret is None or redirect is None:
        return None
    return SlackOAuthClient(cid, secret, redirect)


def build_credential_resolver(vault: Any, settings: Settings) -> Any:
    """Wire ``CredentialResolver`` with provider refresh callbacks when configured."""
    from atlas.governance.credentials import CredentialResolver

    google = build_google_oauth_client(settings)
    slack = build_slack_oauth_client(settings)
    return CredentialResolver(
        vault,
        refresh_google=google.refresh if google else None,
        refresh_slack=slack.refresh if slack else None,
    )
