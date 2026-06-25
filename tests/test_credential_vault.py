"""Credential vault unit tests (M4.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from atlas.governance.credentials import (
    CredentialAccessError,
    CredentialResolver,
    InMemoryCredentialVault,
    OAuthProvider,
    StoredCredential,
    assert_principal_scope,
)
from atlas.governance.rbac import Principal
from atlas.integrations.oauth import GOOGLE_GMAIL_SEND

_MEMBER = Principal(user_id="alice", roles=("member",), org_id="acme")
_OTHER = Principal(user_id="bob", roles=("member",), org_id="acme")
_WRONG_ORG = Principal(user_id="alice", roles=("member",), org_id="other")


def _credential(provider: OAuthProvider = OAuthProvider.GOOGLE) -> StoredCredential:
    return StoredCredential(
        provider=provider,
        scopes=(GOOGLE_GMAIL_SEND,),
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def test_in_memory_vault_round_trip() -> None:
    vault = InMemoryCredentialVault()
    vault.put(_MEMBER, OAuthProvider.GOOGLE, _credential())
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "access-token"
    assert vault.list_connected(_MEMBER) == [OAuthProvider.GOOGLE]


def test_in_memory_vault_idor_wrong_user() -> None:
    vault = InMemoryCredentialVault()
    vault.put(_MEMBER, OAuthProvider.GOOGLE, _credential())
    assert vault.get(_OTHER, OAuthProvider.GOOGLE) is None


def test_require_org_id_rejects_anonymous() -> None:
    with pytest.raises(CredentialAccessError, match="org_id"):
        InMemoryCredentialVault().put(Principal.anonymous(), OAuthProvider.GOOGLE, _credential())


def test_assert_principal_scope_rejects_org_mismatch() -> None:
    with pytest.raises(CredentialAccessError, match="org_id"):
        assert_principal_scope(_WRONG_ORG, "acme", "alice")


def test_resolver_refresh_calls_refresher() -> None:
    vault = InMemoryCredentialVault()
    expired = StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=(GOOGLE_GMAIL_SEND,),
        access_token="old",
        refresh_token="rt",
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    vault.put(_MEMBER, OAuthProvider.GOOGLE, expired)

    def _refresh(token: str) -> StoredCredential:
        assert token == "rt"
        return StoredCredential(
            provider=OAuthProvider.GOOGLE,
            scopes=(GOOGLE_GMAIL_SEND,),
            access_token="new",
            refresh_token="rt",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

    resolver = CredentialResolver(vault, refresh_google=_refresh)
    token = resolver.get_access_token(_MEMBER, OAuthProvider.GOOGLE, frozenset({GOOGLE_GMAIL_SEND}))
    assert token == "new"


def test_resolver_not_connected_raises() -> None:
    resolver = CredentialResolver(InMemoryCredentialVault())
    with pytest.raises(RuntimeError, match="not connected"):
        resolver.get_access_token(_MEMBER, OAuthProvider.GOOGLE, frozenset({GOOGLE_GMAIL_SEND}))
