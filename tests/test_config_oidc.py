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
