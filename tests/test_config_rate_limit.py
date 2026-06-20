"""Rate-limit settings validation (M3.6)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from atlas.config import Settings
from atlas.interface.rate_limit import build_rate_limiter

_UPSTASH_URL = "https://example.upstash.io"
_UPSTASH_TOKEN = SecretStr("tok")


def test_rate_limit_unconfigured_by_default() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    assert not settings.rate_limit_configured
    assert build_rate_limiter(settings) is None


def test_rate_limit_configured_when_both_creds_valid() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        UPSTASH_REDIS_REST_URL=_UPSTASH_URL,
        UPSTASH_REDIS_REST_TOKEN=_UPSTASH_TOKEN,
    )
    assert settings.rate_limit_configured


@pytest.mark.parametrize(
    "kwargs",
    [
        {"UPSTASH_REDIS_REST_URL": "   ", "UPSTASH_REDIS_REST_TOKEN": SecretStr("   ")},
        {"UPSTASH_REDIS_REST_URL": "", "UPSTASH_REDIS_REST_TOKEN": SecretStr("")},
    ],
)
def test_whitespace_or_empty_creds_not_configured(kwargs: dict[str, Any]) -> None:
    settings = Settings(ANTHROPIC_API_KEY=None, **kwargs)
    assert not settings.rate_limit_configured
    assert build_rate_limiter(settings) is None


def test_whitespace_only_creds_do_not_raise() -> None:
    # Dev/CI default: both creds blank/whitespace with limiting enabled is allowed.
    Settings(
        ANTHROPIC_API_KEY=None,
        UPSTASH_REDIS_REST_URL="   ",
        UPSTASH_REDIS_REST_TOKEN=SecretStr("   "),
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"UPSTASH_REDIS_REST_URL": _UPSTASH_URL},
        {"UPSTASH_REDIS_REST_TOKEN": _UPSTASH_TOKEN},
        {"UPSTASH_REDIS_REST_URL": _UPSTASH_URL, "UPSTASH_REDIS_REST_TOKEN": SecretStr("   ")},
        {"UPSTASH_REDIS_REST_URL": "   ", "UPSTASH_REDIS_REST_TOKEN": _UPSTASH_TOKEN},
    ],
)
def test_partial_upstash_config_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="Partial Upstash rate-limit configuration"):
        Settings(ANTHROPIC_API_KEY=None, **kwargs)


def test_partial_upstash_config_allowed_when_limiting_disabled() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_RATE_LIMIT_ENABLED=False,
        UPSTASH_REDIS_REST_URL=_UPSTASH_URL,
    )
    assert not settings.rate_limit_configured
