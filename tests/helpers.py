"""Shared helpers for offline tool/integration tests."""

from __future__ import annotations

from atlas.integrations.email import FakeEmailSender
from atlas.tools import offline_registry

__all__ = ["FakeEmailSender", "offline_registry"]
