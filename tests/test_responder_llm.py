"""OpenRouter-backed responder narration (M4.8d) — offline, hermetic.

Mirrors ``test_extraction.py``'s structure (the same provider-choice pattern): factory selection
from ``Settings``, construction without network, and a ``FakeResponderLLM`` standing in for the LLM
in node-level tests. No network, no Anthropic/OpenRouter key required.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import HumanMessage
from pydantic import ValidationError

from atlas.actions import ActionResult, ProposedAction, RiskTier
from atlas.config import Settings
from atlas.orchestration.nodes import make_responder_node
from atlas.orchestration.responder_llm import (
    FakeResponderLLM,
    ResponderLLM,
    make_responder_llm,
)
from atlas.orchestration.state import AgentState


def _settings(**overrides: object) -> Settings:
    """Build Settings from explicit values only (ignore any developer's local .env)."""
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type, call-arg]


def _state(
    *,
    request: str = "find things",
    proposed: list[ProposedAction] | None = None,
    results: list[ActionResult] | None = None,
    rejected: list[str] | None = None,
) -> AgentState:
    return {
        "messages": [HumanMessage(content=request)],
        "proposed_actions": proposed or [],
        "action_results": results or [],
        "rejected_action_ids": rejected or [],
        "kg_context": [],
    }


# --- factory selection (mirrors make_extractor) -------------------------------
def test_make_responder_llm_defaults_to_none() -> None:
    assert make_responder_llm(_settings()) is None


def test_make_responder_llm_returns_llm_when_enabled_with_key() -> None:
    settings = _settings(OPENROUTER_API_KEY="sk-or-test", ATLAS_RESPONDER_LLM_ENABLED=True)
    assert settings.responder_llm_active is True
    assert isinstance(make_responder_llm(settings), ResponderLLM)


def test_flag_without_key_is_rejected_fail_fast() -> None:
    with pytest.raises(ValidationError):
        _settings(ATLAS_RESPONDER_LLM_ENABLED=True)


def test_key_without_flag_stays_disabled() -> None:
    settings = _settings(OPENROUTER_API_KEY="sk-or-test")
    assert settings.openrouter_configured is True
    assert settings.responder_llm_active is False
    assert make_responder_llm(settings) is None


def test_responder_fallback_model_list_parses_and_trims() -> None:
    settings = _settings(
        ATLAS_RESPONDER_FALLBACK_MODELS="openai/gpt-4o , , google/gemini-flash-1.5"
    )
    assert settings.responder_fallback_model_list == ("openai/gpt-4o", "google/gemini-flash-1.5")


# --- ResponderLLM construction (no network) -----------------------------------
def test_responder_llm_rejects_blank_key() -> None:
    with pytest.raises(ValueError):
        ResponderLLM("   ", "anthropic/claude-opus-4-8")


def test_responder_llm_rejects_blank_model() -> None:
    with pytest.raises(ValueError):
        ResponderLLM("sk-or-test", "   ")


def test_responder_llm_streams_enabled_and_uses_fallbacks() -> None:
    from unittest.mock import MagicMock, patch

    mock_primary = MagicMock()
    mock_fallback = MagicMock()
    mock_composed = MagicMock()
    mock_primary.with_fallbacks.return_value = mock_composed
    mock_composed.invoke.return_value = MagicMock(content="Hello, world.")

    with patch(
        "langchain_openrouter.ChatOpenRouter", side_effect=[mock_primary, mock_fallback]
    ) as mock_ctor:
        narrator = ResponderLLM(
            "sk-or-test", "anthropic/claude-opus-4-8", fallback_models=("openai/gpt-4o",)
        )
        result = narrator.respond("what happened?", "facts here")

    assert result == "Hello, world."
    # Every constructed chat model must have streaming=True (the mechanism token events rely on).
    for call in mock_ctor.call_args_list:
        assert call.kwargs["streaming"] is True
    mock_primary.with_fallbacks.assert_called_once_with([mock_fallback])


def test_responder_llm_flattens_content_block_lists() -> None:
    # Providers may return content as a list of blocks; the user must get the text, never a repr.
    from unittest.mock import MagicMock, patch

    mock_client = MagicMock()
    mock_client.invoke.return_value = MagicMock(
        content=[
            {"type": "text", "text": "hi "},
            {"type": "tool_use"},
            {"type": "text", "text": "there"},
        ]
    )

    with patch("langchain_openrouter.ChatOpenRouter", return_value=mock_client):
        narrator = ResponderLLM("sk-or-test", "anthropic/claude-opus-4-8")
        result = narrator.respond("q", "f")

    assert result == "hi there"


def test_responder_llm_coerces_scalar_non_string_content() -> None:
    from unittest.mock import MagicMock, patch

    mock_client = MagicMock()
    mock_client.invoke.return_value = MagicMock(content=42)

    with patch("langchain_openrouter.ChatOpenRouter", return_value=mock_client):
        narrator = ResponderLLM("sk-or-test", "anthropic/claude-opus-4-8")
        result = narrator.respond("q", "f")

    assert result == "42"


# --- FakeResponderLLM (test double) -------------------------------------------
def test_fake_responder_llm_returns_fixed_response_and_records_calls() -> None:
    fake = FakeResponderLLM("Here is your answer.")
    assert fake.respond("what happened?", "facts") == "Here is your answer."
    assert fake.calls == [("what happened?", "facts")]


def test_fake_responder_llm_can_simulate_failure() -> None:
    fake = FakeResponderLLM("unused", fail=True)
    with pytest.raises(RuntimeError):
        fake.respond("q", "f")


# --- make_responder_node integration (deterministic default + LLM + fallback) -
def test_responder_node_uses_deterministic_summary_by_default() -> None:
    node = make_responder_node(_settings())
    result = node(_state())
    assert result["messages"][0].content == "I did not need to take any actions to answer that."


def test_responder_node_uses_narrator_when_injected() -> None:
    fake = FakeResponderLLM("Here is your answer.")
    node = make_responder_node(_settings(), responder_llm=fake)
    result = node(_state(request="find the roadmap"))
    assert result["messages"][0].content == "Here is your answer."
    assert fake.calls[0][0] == "find the roadmap"
    # The facts block passed to the narrator is the deterministic summary the fallback would use.
    assert "did not need to take any actions" in fake.calls[0][1]


def test_responder_node_falls_back_on_narrator_failure() -> None:
    fake = FakeResponderLLM("unused", fail=True)
    node = make_responder_node(_settings(), responder_llm=fake)
    result = node(_state())
    assert result["messages"][0].content == "I did not need to take any actions to answer that."


def test_responder_node_narrator_never_overrides_confidence_or_sources() -> None:
    # The narrator only rephrases messages content; confidence/sources are still code-computed.
    fake = FakeResponderLLM("A narrated answer.")
    node = make_responder_node(_settings(), responder_llm=fake)
    action = ProposedAction(tool="search", args={"query": "x"}, risk_tier=RiskTier.READ)
    result_ok = ActionResult(action_id=action.action_id, tool="search", ok=True, output={"a": 1})
    result = node(_state(proposed=[action], results=[result_ok]))
    assert result["messages"][0].content == "A narrated answer."
    assert result["confidence"] is not None
    assert isinstance(result["sources"], list)
