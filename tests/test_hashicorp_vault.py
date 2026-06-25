"""HashiCorp Vault credential store integration tests (M4.3)."""

from __future__ import annotations

import os

import pytest
from pydantic import SecretStr

from atlas.config import Settings
from atlas.governance.credentials import OAuthProvider, StoredCredential
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
    settings = Settings(VAULT_ADDR=addr, VAULT_TOKEN=SecretStr(token))
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
