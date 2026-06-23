"""Pluggable Slack post integration (M4.2).

``SlackSender`` is the provider boundary — the managed bot token is owned by the sender
implementation, never by LLM tool args.
"""

from __future__ import annotations

import abc
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr

from atlas.config import Settings

# Slack chat.postMessage documented text limit; reject before API call to avoid silent truncation.
SLACK_MAX_TEXT_CHARS = 40_000


class SlackMessage(BaseModel):
    """Immutable outbound Slack payload (workspace/token is owned by the sender, not the caller)."""

    model_config = ConfigDict(frozen=True)

    channel: str
    text: str


class SlackSender(abc.ABC):
    """Provider-agnostic Slack post contract."""

    @abc.abstractmethod
    def post(self, message: SlackMessage) -> dict[str, Any]:
        """Post ``message`` and return a JSON-able provider result (treated as data, not authz)."""
        raise NotImplementedError


class FakeSlackSender(SlackSender):
    """Records posted messages for demos/tests; never touches the network."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[SlackMessage] = []
        self.fail = fail
        self.call_count = 0

    def post(self, message: SlackMessage) -> dict[str, Any]:
        self.call_count += 1
        if self.fail:
            raise RuntimeError("simulated post failure")
        self.sent.append(message)
        return {"ts": f"fake_{self.call_count}", "channel": message.channel, "provider": "fake"}


class SlackApiSender(SlackSender):
    """Slack Web API backend (sync ``WebClient`` — no global token mutation)."""

    def __init__(self, bot_token: SecretStr) -> None:
        self._bot_token = bot_token

    def post(self, message: SlackMessage) -> dict[str, Any]:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError

        # Disable SDK connection retries: a hidden retry after Slack accepts the post can
        # duplicate the side effect within a single guarded execution.
        client = WebClient(
            token=self._bot_token.get_secret_value(),
            retry_handlers=[],
        )
        try:
            response = client.chat_postMessage(
                channel=message.channel,
                text=message.text,
                unfurl_links=False,
                unfurl_media=False,
            )
        except SlackApiError as exc:
            raise RuntimeError(str(exc)) from exc
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "Slack API error"))
        return {
            "ts": response.get("ts"),
            "channel": response.get("channel"),
            "provider": "slack",
        }


def build_slack_sender(settings: Settings) -> SlackSender | None:
    """Return a configured sender, or ``None`` when Slack is not fully configured."""
    if not settings.slack_configured:
        return None
    bot_token = settings.slack_bot_token
    if bot_token is None:
        return None
    return SlackApiSender(bot_token)
