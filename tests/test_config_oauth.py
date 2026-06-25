"""OAuth + Vault settings validation (M4.3 security fixes)."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from atlas.config import Settings

_GOOGLE_OAUTH = {
    "GOOGLE_OAUTH_CLIENT_ID": "gid",
    "GOOGLE_OAUTH_CLIENT_SECRET": SecretStr("gsecret"),
    "GOOGLE_OAUTH_REDIRECT_URI": "http://localhost/oauth/google/callback",
}


def test_oauth_without_state_secret_rejected() -> None:
    with pytest.raises(ValidationError, match="ATLAS_OAUTH_STATE_SECRET"):
        Settings(ANTHROPIC_API_KEY=None, **_GOOGLE_OAUTH)


def test_oauth_insecure_state_flag_allows_dev() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_OAUTH_ALLOW_INSECURE_STATE=True,
        **_GOOGLE_OAUTH,
    )
    assert settings.oauth_routes_enabled
    assert settings.oauth_allow_insecure_state


def test_oauth_with_state_secret_allowed() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_OAUTH_STATE_SECRET=SecretStr("strong-secret"),
        **_GOOGLE_OAUTH,
    )
    assert settings.oauth_routes_enabled


def test_oauth_with_postgres_without_vault_rejected() -> None:
    with pytest.raises(ValidationError, match="Vault is not configured"):
        Settings(
            ANTHROPIC_API_KEY=None,
            DATABASE_URL=SecretStr("postgresql://atlas:atlas@localhost:5432/atlas"),
            ATLAS_OAUTH_STATE_SECRET=SecretStr("strong-secret"),
            **_GOOGLE_OAUTH,
        )


def test_oauth_with_postgres_and_vault_allowed() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        DATABASE_URL=SecretStr("postgresql://atlas:atlas@localhost:5432/atlas"),
        VAULT_ADDR="http://127.0.0.1:8200",
        VAULT_TOKEN=SecretStr("dev-root-token"),
        ATLAS_OAUTH_STATE_SECRET=SecretStr("strong-secret"),
        **_GOOGLE_OAUTH,
    )
    assert settings.credential_vault_enabled
    assert settings.oauth_routes_enabled
