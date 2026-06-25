"""Pluggable Google Calendar integration (M4.3).

``CalendarClient`` is the provider boundary — the caller's OAuth access token is resolved outside
the client (via ``CredentialResolver``), never from LLM tool args.
"""

from __future__ import annotations

import abc
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

_CALENDAR_EVENTS_URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"


class CalendarEvent(BaseModel):
    """Immutable calendar event payload."""

    model_config = ConfigDict(frozen=True)

    summary: str
    start: str
    end: str
    description: str = ""
    location: str = ""
    timezone: str = "UTC"


class CalendarClient(abc.ABC):
    """Provider-agnostic calendar write contract."""

    @abc.abstractmethod
    def create_event(self, event: CalendarEvent, *, access_token: str) -> dict[str, Any]:
        """Create ``event`` on the user's primary calendar."""
        raise NotImplementedError


class FakeCalendarClient(CalendarClient):
    """Records created events for demos/tests; never touches the network."""

    def __init__(self, *, fail: bool = False) -> None:
        self.created: list[tuple[CalendarEvent, str]] = []
        self.fail = fail
        self.call_count = 0

    def create_event(self, event: CalendarEvent, *, access_token: str) -> dict[str, Any]:
        self.call_count += 1
        if self.fail:
            raise RuntimeError("simulated calendar create failure")
        self.created.append((event, access_token))
        return {
            "id": f"fake_{self.call_count}",
            "provider": "fake",
            "summary": event.summary,
        }


class GoogleCalendarClient(CalendarClient):
    """Google Calendar API backend (sync httpx — no hidden retries)."""

    def create_event(self, event: CalendarEvent, *, access_token: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "summary": event.summary,
            "description": event.description,
            "location": event.location,
            "start": {"dateTime": event.start, "timeZone": event.timezone},
            "end": {"dateTime": event.end, "timeZone": event.timezone},
        }
        response = httpx.post(
            _CALENDAR_EVENTS_URL,
            json=body,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "id": data.get("id"),
            "htmlLink": data.get("htmlLink"),
            "provider": "google_calendar",
            "summary": event.summary,
        }
