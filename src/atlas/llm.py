"""Claude model factory.

Centralizes construction of the chat model so the rest of the system depends on one place for model
selection and credentials. Credentials come only from :class:`atlas.config.Settings` (env).
"""

from __future__ import annotations

from langchain_anthropic import ChatAnthropic

from atlas.config import Settings, get_settings


def build_model(settings: Settings | None = None) -> ChatAnthropic:
    """Construct a Claude chat model from settings.

    Raises ``RuntimeError`` if no API key is configured — callers that want offline behavior should
    check ``settings.has_anthropic_key`` first (the planner does this and falls back to a heuristic).
    """
    settings = settings or get_settings()
    api_key = settings.anthropic_api_key
    if api_key is None or not api_key.get_secret_value():
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set; cannot build a Claude model. "
            "Set it in the environment or use the offline planner path."
        )
    # api_key is narrowed to SecretStr here — an explicit guard, not an assert (asserts are
    # stripped under `python -O` and flagged by Bandit B101).
    return ChatAnthropic(
        model_name=settings.model,
        api_key=api_key,
        timeout=None,
        stop=None,
    )
