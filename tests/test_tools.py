"""Tool registry behavior, including the security invariant that risk tiers come from tools."""

import pytest

from atlas.actions import RiskTier
from atlas.tools import default_registry


def test_send_email_proposal_carries_tool_declared_send_tier() -> None:
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com", "subject": "x", "body": "y"})
    assert action.tool == "send_email"
    assert action.risk_tier is RiskTier.SEND


def test_search_proposal_is_read_tier() -> None:
    registry = default_registry()
    action = registry.propose("search", {"query": "hello"})
    assert action.risk_tier is RiskTier.READ


def test_risk_tier_cannot_be_injected_via_args() -> None:
    # A caller (or a compromised LLM) cannot smuggle a lower risk tier through the args.
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com", "risk_tier": "read"})
    assert action.risk_tier is RiskTier.SEND  # tool wins, always


def test_propose_validates_args_against_schema() -> None:
    registry = default_registry()
    with pytest.raises(Exception):  # missing required 'query'
        registry.propose("search", {})


def test_unknown_tool_is_rejected() -> None:
    registry = default_registry()
    with pytest.raises(KeyError):
        registry.propose("self_destruct", {})


def test_execute_returns_successful_result() -> None:
    registry = default_registry()
    action = registry.propose("search", {"query": "hello"})
    result = registry.execute(action)
    assert result.ok is True
    assert isinstance(result.output, dict)


def test_execute_send_email_unconfigured_returns_failure() -> None:
    from atlas.config import Settings

    registry = default_registry(Settings(RESEND_API_KEY=None, ATLAS_EMAIL_FROM=None))
    action = registry.propose("send_email", {"to": "a@b.com", "subject": "x", "body": "y"})
    result = registry.execute(action)
    assert result.ok is False
