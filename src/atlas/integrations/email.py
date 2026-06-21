"""Pluggable email send integration (M4.1).

``EmailSender`` is the provider boundary — Resend is the first backend; Gmail/Postmark can slot in
later. The ``from`` address is owned by the sender implementation, never by LLM tool args.
"""

from __future__ import annotations

import abc
import json
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, SecretStr

from atlas.config import Settings


class EmailMessage(BaseModel):
    """Immutable outbound email payload (``from`` is owned by the sender, not the caller)."""

    model_config = ConfigDict(frozen=True)

    to: str
    subject: str = ""
    html: str | None = None
    text: str | None = None


class EmailSender(abc.ABC):
    """Provider-agnostic email send contract."""

    @abc.abstractmethod
    def send(self, message: EmailMessage) -> dict[str, Any]:
        """Send ``message`` and return a JSON-able provider result (treated as data, not authz)."""
        raise NotImplementedError


class FakeEmailSender(EmailSender):
    """Records sent messages for demos/tests; never touches the network."""

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


class ResendEmailSender(EmailSender):
    """Resend transactional email backend (sync HTTP — no global ``resend.api_key`` mutation)."""

    def __init__(self, api_key: SecretStr, from_address: str) -> None:
        self._api_key = api_key
        self._from_address = from_address

    def send(self, message: EmailMessage) -> dict[str, Any]:
        import resend
        from resend.version import get_version

        params: dict[str, Any] = {
            "from": self._from_address,
            "to": [message.to],
            "subject": message.subject,
        }
        if message.html is not None:
            params["html"] = message.html
        if message.text is not None:
            params["text"] = message.text

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "User-Agent": f"resend-python:{get_version()}",
        }
        from resend.http_client import HTTPClient

        sync_client = cast(HTTPClient, resend.default_http_client)
        content, status, _resp_headers = sync_client.request(
            method="post",
            url=f"{resend.api_url}/emails",
            headers=headers,
            json=params,
        )
        data: dict[str, Any] = json.loads(content) if content else {}
        if (
            status < 200
            or status >= 300
            or (isinstance(data, dict) and data.get("statusCode") not in (None, 200))
        ):
            from resend.exceptions import raise_for_code_and_type

            code = status if status >= 400 else (data.get("statusCode") or 500)
            raise_for_code_and_type(
                code=code,
                message=data.get("message", "Unknown error")
                if isinstance(data, dict)
                else "Unknown error",
                error_type=data.get("name", "InternalServerError")
                if isinstance(data, dict)
                else "InternalServerError",
            )
        email_id = data.get("id") if isinstance(data, dict) else None
        return {"id": email_id, "provider": "resend", "to": message.to}


def build_email_sender(settings: Settings) -> EmailSender | None:
    """Return a configured sender, or ``None`` when email is not fully configured."""
    if not settings.email_configured:
        return None
    api_key = settings.resend_api_key
    from_addr = settings.email_from
    if api_key is None or from_addr is None:
        return None
    return ResendEmailSender(api_key, from_addr)
