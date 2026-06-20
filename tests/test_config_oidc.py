"""OIDC settings validation (M3.3)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from atlas.config import Settings
from atlas.interface.auth import build_authenticator

_ISSUER = "https://issuer.test/"
_AUDIENCE = "atlas-api"
_JWKS = "https://issuer.test/.well-known/jwks.json"


def test_oidc_all_unset_uses_dev_mode() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    assert not settings.oidc_enabled
    assert build_authenticator(settings) is None


def test_oidc_all_set_is_enabled() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_OIDC_ISSUER=_ISSUER,
        ATLAS_OIDC_AUDIENCE=_AUDIENCE,
        ATLAS_OIDC_JWKS_URI=_JWKS,
    )
    assert settings.oidc_enabled
    assert build_authenticator(settings) is not None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ATLAS_OIDC_ISSUER": _ISSUER},
        {"ATLAS_OIDC_AUDIENCE": _AUDIENCE},
        {"ATLAS_OIDC_JWKS_URI": _JWKS},
        {"ATLAS_OIDC_ISSUER": _ISSUER, "ATLAS_OIDC_AUDIENCE": _AUDIENCE},
        {"ATLAS_OIDC_ISSUER": _ISSUER, "ATLAS_OIDC_JWKS_URI": _JWKS},
        {"ATLAS_OIDC_AUDIENCE": _AUDIENCE, "ATLAS_OIDC_JWKS_URI": _JWKS},
    ],
)
def test_partial_oidc_config_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="Partial OIDC configuration"):
        Settings(ANTHROPIC_API_KEY=None, **kwargs)


def test_insecure_http_oidc_urls_rejected() -> None:
    with pytest.raises(ValidationError, match="ATLAS_OIDC_ISSUER must use https"):
        Settings(
            ANTHROPIC_API_KEY=None,
            ATLAS_OIDC_ISSUER="http://evil.test/",
            ATLAS_OIDC_AUDIENCE=_AUDIENCE,
            ATLAS_OIDC_JWKS_URI=_JWKS,
        )


def test_localhost_http_oidc_urls_allowed() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_OIDC_ISSUER="http://127.0.0.1:8080/",
        ATLAS_OIDC_AUDIENCE=_AUDIENCE,
        ATLAS_OIDC_JWKS_URI="http://localhost:8080/.well-known/jwks.json",
    )
    assert settings.oidc_enabled


def test_insecure_http_allowed_when_opt_in() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_OIDC_ISSUER="http://mock-idp.test/",
        ATLAS_OIDC_AUDIENCE=_AUDIENCE,
        ATLAS_OIDC_JWKS_URI="http://mock-idp.test/jwks.json",
        ATLAS_OIDC_ALLOW_INSECURE_HTTP=True,
    )
    assert settings.oidc_enabled
