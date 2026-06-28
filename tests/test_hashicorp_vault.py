"""HashiCorp Vault credential store integration tests (M4.3)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from hvac.exceptions import VaultError
from pydantic import SecretStr

from atlas.config import Settings
from atlas.governance.credentials import CredentialAccessError, OAuthProvider, StoredCredential
from atlas.governance.rbac import Principal
from atlas.integrations.oauth import GOOGLE_GMAIL_SEND
from atlas.persistence.hashicorp_vault import HashiCorpCredentialVault

_MEMBER = Principal(user_id="alice", roles=("member",), org_id="acme")


@pytest.mark.integration
def test_hashicorp_vault_round_trip() -> None:
    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if not addr or not token:
        pytest.skip("VAULT_ADDR and VAULT_TOKEN required for Vault integration test")
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        VAULT_ADDR=addr,
        VAULT_TOKEN=SecretStr(token),
        ATLAS_OAUTH_STATE_SECRET=SecretStr("test-secret"),
    )
    vault = HashiCorpCredentialVault(settings)
    cred = StoredCredential(
        provider=OAuthProvider.GOOGLE,
        scopes=(GOOGLE_GMAIL_SEND,),
        access_token="integration-token",
        refresh_token="integration-refresh",
    )
    vault.put(_MEMBER, OAuthProvider.GOOGLE, cred)
    stored = vault.get(_MEMBER, OAuthProvider.GOOGLE)
    assert stored is not None
    assert stored.access_token == "integration-token"
    assert OAuthProvider.GOOGLE in vault.list_connected(_MEMBER)
    vault.delete(_MEMBER, OAuthProvider.GOOGLE)
    assert vault.get(_MEMBER, OAuthProvider.GOOGLE) is None


def test_vault_get_network_error_raises_credential_access_error() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        VAULT_ADDR="http://127.0.0.1:8200",
        VAULT_TOKEN=SecretStr("token"),
        ATLAS_OAUTH_STATE_SECRET=SecretStr("test-secret"),
    )
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.side_effect = VaultError("connection refused")
    with patch.object(HashiCorpCredentialVault, "_build_client", return_value=mock_client):
        vault = HashiCorpCredentialVault(settings, setup=False)
    with pytest.raises(CredentialAccessError, match="temporarily unavailable"):
        vault.get(_MEMBER, OAuthProvider.GOOGLE)
