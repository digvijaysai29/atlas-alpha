"""Pluggable Slack user-token post integration (M4.3).

``SlackUserSender`` posts as the authenticated user — the OAuth access token is resolved outside
the sender (via ``CredentialResolver``), never from LLM tool args.
"""

from __future__ import annotations

import abc
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

from atlas.integrations.slack import SLACK_MAX_TEXT_CHARS

_SLACK_POST_URL = "https://slack.com/api/chat.postMessage"


class SlackUserMessage(BaseModel):
    """Immutable outbound Slack user-token payload."""

    model_config = ConfigDict(frozen=True)

    channel: str
    text: str


class SlackUserSender(abc.ABC):
    """Provider-agnostic Slack user post contract."""

    @abc.abstractmethod
    def post(self, message: SlackUserMessage, *, access_token: str) -> dict[str, Any]:
        """Post ``message`` as the authenticated user."""
        raise NotImplementedError


class FakeSlackUserSender(SlackUserSender):
    """Records posted messages for demos/tests; never touches the network."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[tuple[SlackUserMessage, str]] = []
        self.fail = fail
        self.call_count = 0

    def post(self, message: SlackUserMessage, *, access_token: str) -> dict[str, Any]:
        self.call_count += 1
        if self.fail:
            raise RuntimeError("simulated Slack user post failure")
        self.sent.append((message, access_token))
        return {
            "ts": f"fake_{self.call_count}",
            "channel": message.channel,
            "provider": "fake",
        }


class SlackUserApiSender(SlackUserSender):
    """Slack Web API backend using a user OAuth token (sync httpx — no hidden retries)."""

    def post(self, message: SlackUserMessage, *, access_token: str) -> dict[str, Any]:
        if len(message.text) > SLACK_MAX_TEXT_CHARS:
            raise ValueError(f"text exceeds Slack limit ({SLACK_MAX_TEXT_CHARS} chars)")
        response = httpx.post(
            _SLACK_POST_URL,
            json={
                "channel": message.channel,
                "text": message.text,
                "unfurl_links": False,
                "unfurl_media": False,
            },
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            raise RuntimeError(data.get("error", "Slack API error"))
        return {
            "ts": data.get("ts"),
            "channel": data.get("channel"),
            "provider": "slack_user",
        }
