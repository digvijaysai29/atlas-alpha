"""Per-principal OAuth credential vault (M4.3).

``CredentialVault`` is the storage boundary — HashiCorp Vault KV v2 is the production backend;
``InMemoryCredentialVault`` is the hermetic test double. Tokens never enter graph state, audit
detail, or logs.
"""

from __future__ import annotations

import abc
import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from atlas.governance.rbac import Principal

logger = logging.getLogger("atlas.governance.credentials")

# Refresh when expiry is within this window (seconds).
_TOKEN_REFRESH_SKEW_SECONDS = 120


class OAuthProvider(str, Enum):
    """Supported outbound OAuth integrations."""

    GOOGLE = "google"
    SLACK = "slack"


class StoredCredential(BaseModel):
    """In-memory representation of a stored OAuth token set (never serialized to audit)."""

    model_config = ConfigDict(frozen=True)

    provider: OAuthProvider
    scopes: tuple[str, ...] = Field(default_factory=tuple)
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    token_type: str = "Bearer"
    metadata: dict[str, str] = Field(default_factory=dict)


class CredentialVault(abc.ABC):
    """Provider-agnostic contract for per-principal OAuth token storage."""

    @abc.abstractmethod
    def put(
        self, principal: Principal, provider: OAuthProvider, credential: StoredCredential
    ) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, principal: Principal, provider: OAuthProvider) -> StoredCredential | None:
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, principal: Principal, provider: OAuthProvider) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def list_connected(self, principal: Principal) -> list[OAuthProvider]:
        raise NotImplementedError


class CredentialAccessError(RuntimeError):
    """Raised when credential access is denied or the principal lacks required identity."""


def require_org_id(principal: Principal) -> str:
    """Fail-closed: OAuth credentials are scoped to (org_id, user_id)."""
    if not principal.org_id or principal.org_id.strip() == "":
        raise CredentialAccessError("org_id is required for credential storage")
    if principal == Principal.anonymous():
        raise CredentialAccessError("anonymous principal cannot access credentials")
    return principal.org_id


def vault_path_segment(value: str) -> str:
    """Sanitize a path segment — block traversal and Vault path separators."""
    cleaned = value.strip().replace("/", "_").replace("\\", "_").replace(".", "_")
    if not cleaned:
        raise CredentialAccessError("empty path segment")
    return cleaned


def credential_secret_path(mount: str, org_id: str, user_id: str, provider: OAuthProvider) -> str:
    """KV v2 logical path (without ``/data/`` prefix — hvac adds mount)."""
    org = vault_path_segment(org_id)
    user = vault_path_segment(user_id)
    return f"{mount.strip('/')}/atlas/credentials/{org}/{user}/{provider.value}"


def assert_principal_scope(principal: Principal, org_id: str, user_id: str) -> None:
    """IDOR defense: the authenticated principal must match the storage key."""
    require_org_id(principal)
    if principal.user_id != user_id:
        raise CredentialAccessError("credential access denied for user_id")
    if principal.org_id != org_id:
        raise CredentialAccessError("credential access denied for org_id")


class InMemoryCredentialVault(CredentialVault):
    """Hermetic vault for unit tests and offline demos."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str, OAuthProvider], StoredCredential] = {}

    def _key(self, principal: Principal, provider: OAuthProvider) -> tuple[str, str, OAuthProvider]:
        org_id = require_org_id(principal)
        return (org_id, principal.user_id, provider)

    def put(
        self, principal: Principal, provider: OAuthProvider, credential: StoredCredential
    ) -> None:
        require_org_id(principal)
        self._store[self._key(principal, provider)] = credential

    def get(self, principal: Principal, provider: OAuthProvider) -> StoredCredential | None:
        require_org_id(principal)
        return self._store.get(self._key(principal, provider))

    def delete(self, principal: Principal, provider: OAuthProvider) -> None:
        require_org_id(principal)
        self._store.pop(self._key(principal, provider), None)

    def list_connected(self, principal: Principal) -> list[OAuthProvider]:
        org_id = require_org_id(principal)
        return sorted(
            {
                provider
                for (o, u, provider) in self._store
                if o == org_id and u == principal.user_id
            },
            key=lambda p: p.value,
        )


class CredentialResolver:
    """Resolve a valid access token for a principal, refreshing via OAuth when expired."""

    def __init__(
        self,
        vault: CredentialVault,
        *,
        refresh_google: Any | None = None,
        refresh_slack: Any | None = None,
    ) -> None:
        self._vault = vault
        self._refresh_google = refresh_google
        self._refresh_slack = refresh_slack

    def get_access_token(
        self,
        principal: Principal,
        provider: OAuthProvider,
        required_scopes: frozenset[str],
    ) -> str:
        stored = self._vault.get(principal, provider)
        if stored is None:
            raise RuntimeError(
                f"{provider.value} not connected — visit /oauth/{provider.value}/connect"
            )
        missing = required_scopes - frozenset(stored.scopes)
        if missing:
            raise RuntimeError(
                f"{provider.value} missing scopes {sorted(missing)} — reconnect via "
                f"/oauth/{provider.value}/connect"
            )
        if self._needs_refresh(stored):
            stored = self._refresh(principal, provider, stored)
        return stored.access_token

    def _needs_refresh(self, stored: StoredCredential) -> bool:
        if stored.expires_at is None:
            return False
        now = datetime.now(UTC)
        expires = stored.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return expires <= now + timedelta(seconds=_TOKEN_REFRESH_SKEW_SECONDS)

    def _refresh(
        self,
        principal: Principal,
        provider: OAuthProvider,
        stored: StoredCredential,
    ) -> StoredCredential:
        if not stored.refresh_token:
            raise RuntimeError(f"{provider.value} token expired and no refresh token — reconnect")
        refresher = (
            self._refresh_google if provider is OAuthProvider.GOOGLE else self._refresh_slack
        )
        if refresher is None:
            raise RuntimeError(f"{provider.value} refresh not configured")
        updated: StoredCredential = refresher(stored.refresh_token)
        self._vault.put(principal, provider, updated)
        return updated
