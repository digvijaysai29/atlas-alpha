"""Slack integration tests (offline fake sender + optional live Slack)."""

from __future__ import annotations

import os

import pytest
from pydantic import SecretStr, ValidationError

from atlas.config import Settings
from atlas.integrations.slack import (
    SLACK_MAX_TEXT_CHARS,
    FakeSlackSender,
    SlackMessage,
    build_slack_sender,
)
from atlas.tools import SlackPostTool, default_registry


def test_slack_post_tool_uses_injected_sender() -> None:
    sender = FakeSlackSender()
    tool = SlackPostTool(sender=sender)
    output = tool.run(tool.ArgsSchema.model_validate({"channel": "#general", "text": "hello"}))
    assert output["provider"] == "fake"
    assert len(sender.sent) == 1
    assert sender.sent[0].channel == "#general"


def test_slack_post_without_sender_raises() -> None:
    tool = SlackPostTool(sender=None)
    with pytest.raises(RuntimeError, match="slack not configured"):
        tool.run(tool.ArgsSchema.model_validate({"channel": "#general", "text": "hi"}))


def test_build_slack_sender_none_when_unconfigured() -> None:
    settings = Settings(SLACK_BOT_TOKEN=None)
    assert build_slack_sender(settings) is None


def test_build_slack_sender_returns_api_sender_when_configured() -> None:
    settings = Settings(SLACK_BOT_TOKEN=SecretStr("xoxb-test"))
    sender = build_slack_sender(settings)
    assert sender is not None
    assert sender.__class__.__name__ == "SlackApiSender"


def test_slack_api_sender_maps_response(monkeypatch: pytest.MonkeyPatch) -> None:
    from atlas.integrations.slack import SlackApiSender

    class _FakeWebClient:
        def __init__(self, token: str, *, retry_handlers: list[object] | None = None) -> None:
            self.token = token
            self.retry_handlers = retry_handlers

        def chat_postMessage(
            self,
            *,
            channel: str,
            text: str,
            unfurl_links: bool | None = None,
            unfurl_media: bool | None = None,
        ) -> dict[str, object]:
            assert unfurl_links is False
            assert unfurl_media is False
            return {"ok": True, "ts": "123.456", "channel": "C123"}

    import slack_sdk

    monkeypatch.setattr(slack_sdk, "WebClient", _FakeWebClient)
    sender = SlackApiSender(SecretStr("xoxb-test"))
    result = sender.post(SlackMessage(channel="#general", text="hi"))
    assert result == {"ts": "123.456", "channel": "C123", "provider": "slack"}


def test_slack_api_sender_disables_sdk_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    from atlas.integrations.slack import SlackApiSender

    captured: dict[str, object] = {}

    class _FakeWebClient:
        def __init__(self, token: str, *, retry_handlers: list[object] | None = None) -> None:
            captured["retry_handlers"] = retry_handlers

        def chat_postMessage(self, **kwargs: object) -> dict[str, object]:
            return {"ok": True, "ts": "1", "channel": "C1"}

    import slack_sdk

    monkeypatch.setattr(slack_sdk, "WebClient", _FakeWebClient)
    SlackApiSender(SecretStr("xoxb-test")).post(SlackMessage(channel="#general", text="hi"))
    assert captured["retry_handlers"] == []


def test_slack_api_sender_raises_on_slack_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from atlas.integrations.slack import SlackApiSender
    from slack_sdk.errors import SlackApiError

    class _FakeResponse:
        def get(self, key: str, default: object = None) -> object:
            return {"error": "invalid_auth"}.get(key, default)

    class _FakeWebClient:
        def __init__(self, token: str, **kwargs: object) -> None:
            pass

        def chat_postMessage(self, *, channel: str, text: str, **kwargs: object) -> dict[str, object]:
            raise SlackApiError("The request to the Slack API failed.", _FakeResponse())  # type: ignore[no-untyped-call]

    import slack_sdk

    monkeypatch.setattr(slack_sdk, "WebClient", _FakeWebClient)
    sender = SlackApiSender(SecretStr("xoxb-test"))
    with pytest.raises(RuntimeError, match="Slack API"):
        sender.post(SlackMessage(channel="#bad", text="hi"))


def test_slack_api_sender_raises_on_not_ok_response(monkeypatch: pytest.MonkeyPatch) -> None:
    from atlas.integrations.slack import SlackApiSender

    class _FakeWebClient:
        def __init__(self, token: str, **kwargs: object) -> None:
            pass

        def chat_postMessage(self, *, channel: str, text: str, **kwargs: object) -> dict[str, object]:
            return {"ok": False, "error": "channel_not_found"}

    import slack_sdk

    monkeypatch.setattr(slack_sdk, "WebClient", _FakeWebClient)
    sender = SlackApiSender(SecretStr("xoxb-test"))
    with pytest.raises(RuntimeError, match="channel_not_found"):
        sender.post(SlackMessage(channel="#bad", text="hi"))


def test_default_registry_disables_real_slack_without_durable_audit() -> None:
    settings = Settings(
        SLACK_BOT_TOKEN=SecretStr("xoxb-test"),
        DATABASE_URL=None,
    )
    registry = default_registry(settings)
    action = registry.propose("slack_post", {"channel": "#general", "text": "y"})
    result = registry.execute(action)
    assert result.ok is False


def test_slack_post_rejects_user_and_dm_channel_ids() -> None:
    tool = SlackPostTool(sender=FakeSlackSender())
    for channel in ("U01234567", "D01234567", "u01234567", "@alice"):
        with pytest.raises(ValidationError):
            tool.ArgsSchema.model_validate({"channel": channel, "text": "hi"})


def test_slack_post_rejects_user_channel_at_propose_boundary() -> None:
    registry = default_registry()
    with pytest.raises(ValidationError):
        registry.propose("slack_post", {"channel": "U01234567", "text": "hi"})


def test_slack_post_accepts_channel_targets() -> None:
    tool = SlackPostTool(sender=FakeSlackSender())
    for channel in ("#general", "C01234567", "general"):
        args = tool.ArgsSchema.model_validate({"channel": channel, "text": "hi"})
        assert args.channel == channel


def test_slack_post_rejects_oversized_text() -> None:
    tool = SlackPostTool(sender=FakeSlackSender())
    with pytest.raises(ValidationError):
        tool.ArgsSchema.model_validate(
            {"channel": "#general", "text": "x" * (SLACK_MAX_TEXT_CHARS + 1)}
        )
    args = tool.ArgsSchema.model_validate(
        {"channel": "#general", "text": "x" * SLACK_MAX_TEXT_CHARS}
    )
    assert len(args.text) == SLACK_MAX_TEXT_CHARS


@pytest.mark.integration
def test_live_slack_post() -> None:
    if os.environ.get("ATLAS_SLACK_LIVE_TEST", "").lower() not in ("1", "true", "yes"):
        pytest.skip("Set ATLAS_SLACK_LIVE_TEST=1 to run live Slack post")
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("ATLAS_SLACK_CHANNEL")
    if not token or not channel:
        pytest.skip("SLACK_BOT_TOKEN/ATLAS_SLACK_CHANNEL not set for live post")
    settings = Settings(SLACK_BOT_TOKEN=SecretStr(token))
    sender = build_slack_sender(settings)
    assert sender is not None
    result = sender.post(SlackMessage(channel=channel, text="atlas M4.2 integration test"))
    assert result.get("ts")
