"""Tool registry behavior, including the security invariant that risk tiers come from tools."""

import pytest

from atlas.actions import RiskTier
from atlas.governance.rbac import Principal
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
    result = registry.execute(action, Principal(user_id="test", roles=("member",), org_id="org1"))
    assert result.ok is True
    assert isinstance(result.output, dict)


def test_execute_send_email_unconfigured_returns_failure() -> None:
    from atlas.config import Settings

    registry = default_registry(Settings(RESEND_API_KEY=None, ATLAS_EMAIL_FROM=None))
    action = registry.propose("send_email", {"to": "a@b.com", "subject": "x", "body": "y"})
    result = registry.execute(action, Principal(user_id="test", roles=("member",), org_id="org1"))
    assert result.ok is False


# --- resource-scoped permission stamping (M4.8c) ----------------------------
def test_send_email_permission_is_scoped_by_recipient_domain() -> None:
    registry = default_registry()
    action = registry.propose(
        "send_email", {"to": "alice@Company.COM", "subject": "x", "body": "y"}
    )
    assert action.required_permission == "tool:send:domain:company.com"


def test_gmail_send_permission_is_scoped_by_recipient_domain() -> None:
    registry = default_registry()
    action = registry.propose("gmail_send", {"to": "bob@example.org", "subject": "x", "body": "y"})
    assert action.required_permission == "tool:gmail:send:domain:example.org"


def test_slack_post_permission_is_scoped_by_channel() -> None:
    # "#name" is unambiguously a channel *name* and Slack names are lowercase-only, so the segment
    # is normalized — "#General" matches a "channel:general" grant (parity with lowercased email
    # domains). Channel IDs stay verbatim (see the raw-ID test below).
    registry = default_registry()
    action = registry.propose("slack_post", {"channel": "#General", "text": "hi"})
    assert action.required_permission == "tool:slack:post:channel:general"


def test_slack_post_permission_uses_raw_channel_id_unchanged() -> None:
    registry = default_registry()
    action = registry.propose("slack_post", {"channel": "C123ABC", "text": "hi"})
    assert action.required_permission == "tool:slack:post:channel:C123ABC"


def test_search_permission_is_not_resource_scoped() -> None:
    # search has no required_permission at all; combining with a resource segment is a no-op.
    registry = default_registry()
    action = registry.propose("search", {"query": "hello"})
    assert action.required_permission is None


def test_slack_post_as_user_permission_is_not_resource_scoped() -> None:
    # Deliberately unscoped (M4.8c): it has a schema-driven twin in the adapter engine, and scoping
    # only the hand-written side would break the M4.8a hand-written/schema equivalence guarantee.
    registry = default_registry()
    action = registry.propose("slack_post_as_user", {"channel": "#general", "text": "hi"})
    assert action.required_permission == "tool:slack:post_as_user"


def test_permission_scope_cannot_be_injected_via_args() -> None:
    # A caller (or a compromised LLM) cannot smuggle a different resource scope by passing extra
    # fields — only the tool's own ArgsSchema-validated fields feed resource_permission().
    registry = default_registry()
    action = registry.propose(
        "send_email",
        {"to": "a@b.com", "subject": "x", "body": "y", "required_permission": "tool:admin:*"},
    )
    assert action.required_permission == "tool:send:domain:b.com"


@pytest.mark.parametrize("tool_name", ["send_email", "gmail_send"])
@pytest.mark.parametrize("bad_to", ["ab@", "@b.com", "nodomain", "a b@c.com", "a@b @c"])
def test_malformed_recipient_rejected_at_schema_boundary(tool_name: str, bad_to: str) -> None:
    # "ab@" would otherwise scope to an empty "domain:" segment, which a "domain:*" wildcard grant
    # still matches — malformed addresses must never reach resource_permission().
    registry = default_registry()
    with pytest.raises(ValueError, match="recipient"):
        registry.propose(tool_name, {"to": bad_to, "subject": "x", "body": "y"})
