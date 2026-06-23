"""Shared helpers for offline tool/integration tests."""

from __future__ import annotations

from atlas.integrations.email import FakeEmailSender
from atlas.integrations.slack import FakeSlackSender
from atlas.tools import offline_registry

__all__ = ["FakeEmailSender", "FakeSlackSender", "offline_registry"]
