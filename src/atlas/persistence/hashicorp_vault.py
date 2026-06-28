"""HashiCorp Vault KV v2 backend for per-principal OAuth credentials (M4.3)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import hvac
from hvac.exceptions import InvalidPath, VaultError

from atlas.config import Settings
from atlas.governance.credentials import (
    CredentialAccessError,
    CredentialVault,
    OAuthProvider,
    StoredCredential,
    assert_principal_scope,
    credential_secret_path,
    require_org_id,
    vault_path_segment,
)
from atlas.governance.rbac import Principal

logger = logging.getLogger("atlas.persistence.hashicorp_vault")


def _parse_expires_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _serialize_credential(credential: StoredCredential) -> dict[str, Any]:
    return {
        "access_token": credential.access_token,
        "refresh_token": credential.refresh_token,
        "token_type": credential.token_type,
        "scopes": list(credential.scopes),
        "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
        "metadata": dict(credential.metadata),
    }


def _deserialize_credential(provider: OAuthProvider, payload: dict[str, Any]) -> StoredCredential:
    scopes_raw = payload.get("scopes") or []
    metadata_raw = payload.get("metadata") or {}
    return StoredCredential(
        provider=provider,
        scopes=tuple(str(s) for s in scopes_raw),
        access_token=str(payload["access_token"]),
        refresh_token=payload.get("refresh_token"),
        expires_at=_parse_expires_at(payload.get("expires_at")),
        token_type=str(payload.get("token_type") or "Bearer"),
        metadata={str(k): str(v) for k, v in metadata_raw.items()},
    )


class HashiCorpCredentialVault(CredentialVault):
    """Durable credential store backed by Vault KV secrets engine v2."""

    def __init__(self, settings: Settings, *, setup: bool = True) -> None:
        self._settings = settings
        self._mount = settings.vault_mount.strip("/") or "secret"
        self._client = self._build_client(settings)
        if setup:
            self.setup()

    @staticmethod
    def _build_client(settings: Settings) -> hvac.Client:
        addr = settings.vault_addr
        if not addr:
            raise CredentialAccessError("VAULT_ADDR is required for HashiCorpCredentialVault")
        client = hvac.Client(url=addr.strip(), namespace=(settings.vault_namespace or ""))
        if settings.vault_token is not None:
            client.token = settings.vault_token.get_secret_value()
        elif settings.vault_role_id and settings.vault_secret_id is not None:
            response = client.auth.approle.login(
                role_id=settings.vault_role_id,
                secret_id=settings.vault_secret_id.get_secret_value(),
            )
            client.token = response["auth"]["client_token"]
        else:
            raise CredentialAccessError("Vault authentication not configured")
        if not client.is_authenticated():
            raise CredentialAccessError("Vault authentication failed")
        return client

    def setup(self) -> None:
        """Ensure the KV v2 mount exists (dev convenience; prod is provisioned by ops)."""
        try:
            mounts = self._client.sys.list_mounted_secrets_engines()
            if f"{self._mount}/" not in mounts.get("data", {}):
                self._client.sys.enable_secrets_engine(
                    backend_type="kv",
                    path=self._mount,
                    options={"version": "2"},
                )
        except VaultError as exc:
            logger.warning("Vault setup skipped or failed: %s", type(exc).__name__)

    def _relative_path(self, org_id: str, user_id: str, provider: OAuthProvider) -> str:
        full = credential_secret_path(self._mount, org_id, user_id, provider)
        return full.removeprefix(f"{self._mount}/")

    def put(
        self, principal: Principal, provider: OAuthProvider, credential: StoredCredential
    ) -> None:
        org_id = require_org_id(principal)
        assert_principal_scope(principal, org_id, principal.user_id)
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=self._relative_path(org_id, principal.user_id, provider),
                secret=_serialize_credential(credential),
                mount_point=self._mount,
            )
        except VaultError as exc:
            logger.warning("Vault put failed: %s", type(exc).__name__)
            raise CredentialAccessError("credential store temporarily unavailable") from exc

    def get(self, principal: Principal, provider: OAuthProvider) -> StoredCredential | None:
        org_id = require_org_id(principal)
        assert_principal_scope(principal, org_id, principal.user_id)
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=self._relative_path(org_id, principal.user_id, provider),
                mount_point=self._mount,
            )
        except InvalidPath:
            return None
        except VaultError as exc:
            logger.warning("Vault get failed: %s", type(exc).__name__)
            raise CredentialAccessError("credential store temporarily unavailable") from exc
        data = response.get("data", {}).get("data")
        if not isinstance(data, dict):
            return None
        return _deserialize_credential(provider, data)

    def delete(self, principal: Principal, provider: OAuthProvider) -> None:
        org_id = require_org_id(principal)
        assert_principal_scope(principal, org_id, principal.user_id)
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._relative_path(org_id, principal.user_id, provider),
                mount_point=self._mount,
            )
        except InvalidPath:
            return
        except VaultError as exc:
            logger.warning("Vault delete failed: %s", type(exc).__name__)
            raise CredentialAccessError("credential store temporarily unavailable") from exc

    def list_connected(self, principal: Principal) -> list[OAuthProvider]:
        org_id = require_org_id(principal)
        assert_principal_scope(principal, org_id, principal.user_id)
        prefix = (
            f"atlas/credentials/{vault_path_segment(org_id)}/"
            f"{vault_path_segment(principal.user_id)}"
        )
        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=prefix,
                mount_point=self._mount,
            )
        except InvalidPath:
            return []
        except VaultError as exc:
            logger.warning("Vault list failed: %s", type(exc).__name__)
            raise CredentialAccessError("credential store temporarily unavailable") from exc
        keys = response.get("data", {}).get("keys") or []
        connected: list[OAuthProvider] = []
        for key in keys:
            name = str(key).strip("/")
            try:
                connected.append(OAuthProvider(name))
            except ValueError:
                continue
        return sorted(connected, key=lambda p: p.value)
