"""Gmail, Calendar, and Slack-as-user integration tests (M4.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from atlas.governance.credentials import (
    CredentialResolver,
    InMemoryCredentialVault,
    OAuthProvider,
    StoredCredential,
)
from atlas.governance.rbac import Principal
from atlas.integrations.calendar import FakeCalendarClient
from atlas.integrations.gmail import FakeGmailSender
from atlas.integrations.oauth import (
    GOOGLE_CALENDAR_EVENTS,
    GOOGLE_GMAIL_SEND,
    SLACK_USER_CHAT_WRITE,
)
from atlas.integrations.slack_user import FakeSlackUserSender
from atlas.tools import (
    CalendarCreateEventTool,
    GmailSendTool,
    SlackPostAsUserTool,
    offline_registry,
)

_MEMBER = Principal(user_id="alice", roles=("member",), org_id="acme")


def _resolver_with_google() -> CredentialResolver:
    vault = InMemoryCredentialVault()
    vault.put(
        _MEMBER,
        OAuthProvider.GOOGLE,
        StoredCredential(
            provider=OAuthProvider.GOOGLE,
            scopes=(GOOGLE_GMAIL_SEND, GOOGLE_CALENDAR_EVENTS),
            access_token="google-token",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    return CredentialResolver(vault)


def _resolver_with_slack() -> CredentialResolver:
    vault = InMemoryCredentialVault()
    vault.put(
        _MEMBER,
        OAuthProvider.SLACK,
        StoredCredential(
            provider=OAuthProvider.SLACK,
            scopes=(SLACK_USER_CHAT_WRITE,),
            access_token="slack-token",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    return CredentialResolver(vault)


def test_gmail_send_tool_uses_resolver() -> None:
    sender = FakeGmailSender()
    tool = GmailSendTool(sender=sender, credential_resolver=_resolver_with_google())
    output = tool.run(
        tool.ArgsSchema.model_validate({"to": "a@b.com", "subject": "hi", "body": "x"}),
        principal=_MEMBER,
    )
    assert output["provider"] == "fake"
    assert sender.call_count == 1


def test_calendar_create_event_tool() -> None:
    client = FakeCalendarClient()
    tool = CalendarCreateEventTool(client=client, credential_resolver=_resolver_with_google())
    output = tool.run(
        tool.ArgsSchema.model_validate(
            {
                "summary": "Standup",
                "start": "2026-06-26T10:00:00Z",
                "end": "2026-06-26T10:30:00Z",
            }
        ),
        principal=_MEMBER,
    )
    assert output["provider"] == "fake"
    assert client.call_count == 1


def test_slack_post_as_user_tool() -> None:
    sender = FakeSlackUserSender()
    tool = SlackPostAsUserTool(sender=sender, credential_resolver=_resolver_with_slack())
    output = tool.run(
        tool.ArgsSchema.model_validate({"channel": "#general", "text": "hello"}),
        principal=_MEMBER,
    )
    assert output["provider"] == "fake"
    assert sender.call_count == 1


def test_offline_registry_includes_oauth_tools() -> None:
    registry = offline_registry()
    names = registry.names()
    assert "gmail_send" in names
    assert "calendar_create_event" in names
    assert "slack_post_as_user" in names


def test_gmail_not_connected_raises() -> None:
    tool = GmailSendTool(
        sender=FakeGmailSender(),
        credential_resolver=CredentialResolver(InMemoryCredentialVault()),
    )
    with pytest.raises(RuntimeError, match="not connected"):
        tool.run(
            tool.ArgsSchema.model_validate({"to": "a@b.com"}),
            principal=_MEMBER,
        )
