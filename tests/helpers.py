"""Shared helpers for offline tool/integration tests."""

from __future__ import annotations

from typing import Any

from atlas.integrations.email import EmailMessage, EmailSender
from atlas.tools import SearchTool, SendEmailTool, ToolRegistry


class FakeEmailSender(EmailSender):
    """Records sent messages for assertions; never touches the network."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[EmailMessage] = []
        self.fail = fail
        self.call_count = 0

    def send(self, message: EmailMessage) -> dict[str, Any]:
        self.call_count += 1
        if self.fail:
            raise RuntimeError("simulated send failure")
        self.sent.append(message)
        return {"id": f"fake_{self.call_count}", "provider": "fake", "to": message.to}


def offline_registry(sender: EmailSender | None = None) -> ToolRegistry:
    """Registry with a fake email sender so gated send tests stay offline."""
    registry = ToolRegistry()
    registry.register(SearchTool())
    registry.register(SendEmailTool(sender=sender or FakeEmailSender()))
    return registry
