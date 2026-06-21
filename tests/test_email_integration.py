"""Email integration tests (offline fake sender + optional live Resend)."""

from __future__ import annotations

import os

import pytest
from pydantic import SecretStr

from atlas.config import Settings
from atlas.integrations.email import EmailMessage, build_email_sender
from atlas.tools import SendEmailTool, default_registry
from tests.helpers import FakeEmailSender


def test_send_email_tool_uses_injected_sender() -> None:
    sender = FakeEmailSender()
    tool = SendEmailTool(sender=sender)
    output = tool.run(
        tool.ArgsSchema.model_validate({"to": "a@b.com", "subject": "hi", "body": "x"})
    )
    assert output["provider"] == "fake"
    assert len(sender.sent) == 1
    assert sender.sent[0].to == "a@b.com"


def test_send_email_without_sender_raises() -> None:
    tool = SendEmailTool(sender=None)
    with pytest.raises(RuntimeError, match="email not configured"):
        tool.run(tool.ArgsSchema.model_validate({"to": "a@b.com"}))


def test_build_email_sender_none_when_unconfigured() -> None:
    settings = Settings(RESEND_API_KEY=None, ATLAS_EMAIL_FROM=None)
    assert build_email_sender(settings) is None


def test_build_email_sender_returns_resend_when_configured() -> None:
    settings = Settings(
        RESEND_API_KEY=SecretStr("re_test"),
        ATLAS_EMAIL_FROM="atlas@example.com",
    )
    sender = build_email_sender(settings)
    assert sender is not None
    assert sender.__class__.__name__ == "ResendEmailSender"


def test_partial_email_config_rejected() -> None:
    with pytest.raises(ValueError, match="Partial email configuration"):
        Settings(RESEND_API_KEY=SecretStr("re_test"), ATLAS_EMAIL_FROM=None)


@pytest.mark.integration
def test_live_resend_send() -> None:
    key = os.environ.get("RESEND_API_KEY")
    from_addr = os.environ.get("ATLAS_EMAIL_FROM")
    to_addr = os.environ.get("ATLAS_EMAIL_TO", from_addr)
    if not key or not from_addr or not to_addr:
        pytest.skip("RESEND_API_KEY/ATLAS_EMAIL_FROM not set for live send")
    settings = Settings(RESEND_API_KEY=SecretStr(key), ATLAS_EMAIL_FROM=from_addr)
    sender = build_email_sender(settings)
    assert sender is not None
    result = sender.send(EmailMessage(to=to_addr, subject="atlas M4.1", text="integration test"))
    assert result.get("id")
