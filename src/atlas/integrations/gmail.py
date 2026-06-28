"""Pluggable Gmail send integration (M4.3).

``GmailSender`` is the provider boundary — the caller's OAuth access token is resolved outside the
sender (via ``CredentialResolver``), never from LLM tool args.
"""

from __future__ import annotations

import abc
import base64
from email.mime.text import MIMEText
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

_GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


class GmailMessage(BaseModel):
    """Immutable outbound Gmail payload."""

    model_config = ConfigDict(frozen=True)

    to: str
    subject: str = ""
    text: str | None = None
    html: str | None = None


class GmailSender(abc.ABC):
    """Provider-agnostic Gmail send contract."""

    @abc.abstractmethod
    def send(self, message: GmailMessage, *, access_token: str) -> dict[str, Any]:
        """Send ``message`` as the authenticated user and return a JSON-able provider result."""
        raise NotImplementedError


class FakeGmailSender(GmailSender):
    """Records sent messages for demos/tests; never touches the network."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[tuple[GmailMessage, str]] = []
        self.fail = fail
        self.call_count = 0

    def send(self, message: GmailMessage, *, access_token: str) -> dict[str, Any]:
        self.call_count += 1
        if self.fail:
            raise RuntimeError("simulated Gmail send failure")
        self.sent.append((message, access_token))
        return {
            "id": f"fake_{self.call_count}",
            "provider": "fake",
            "to": message.to,
        }


def _encode_rfc822(message: GmailMessage) -> str:
    if message.html is not None:
        mime = MIMEText(message.html, "html")
    else:
        mime = MIMEText(message.text or "")
    mime["to"] = message.to
    mime["subject"] = message.subject
    return base64.urlsafe_b64encode(mime.as_bytes()).decode("ascii")


class GmailApiSender(GmailSender):
    """Gmail API backend (sync httpx — no hidden retries)."""

    def send(self, message: GmailMessage, *, access_token: str) -> dict[str, Any]:
        response = httpx.post(
            _GMAIL_SEND_URL,
            json={"raw": _encode_rfc822(message)},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "id": data.get("id"),
            "provider": "gmail",
            "to": message.to,
        }
