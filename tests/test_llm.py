"""The model factory's offline-safety contract.

atlas must run with no API key (planner falls back to a heuristic). These tests pin that contract:
``has_anthropic_key`` is False without a key, and ``build_model`` fails loudly rather than silently.
"""

import pytest

from atlas.config import Settings
from atlas.llm import build_model


def test_settings_reports_no_key_when_absent() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    assert settings.has_anthropic_key is False


def test_build_model_raises_without_a_key() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        build_model(settings)
