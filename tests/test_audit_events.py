"""Audit ledger extensions for idempotent execution (M4.1)."""

import pytest

from atlas.actions import ActionResult
from atlas.governance import AuditEventType, InMemoryAuditLog
from atlas.tools import default_registry


def test_has_executed_false_until_success() -> None:
    log = InMemoryAuditLog()
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com"})
    assert log.has_executed(action.action_id) is False


def test_has_executed_true_after_executed_event() -> None:
    log = InMemoryAuditLog()
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com"})
    log.executed(ActionResult(action_id=action.action_id, tool="send_email", ok=True, output={}))
    assert log.has_executed(action.action_id) is True


def test_executed_rejects_failed_result() -> None:
    log = InMemoryAuditLog()
    result = ActionResult(action_id="act_x", tool="send_email", ok=False, error="boom")
    with pytest.raises(ValueError, match="success-only"):
        log.executed(result)


def test_failed_records_failed_event_not_executed() -> None:
    log = InMemoryAuditLog()
    result = ActionResult(action_id="act_x", tool="send_email", ok=False, error="boom")
    log.failed(result)
    assert log.has_executed("act_x") is False
    assert log.events()[-1].event_type is AuditEventType.FAILED


def test_replay_skipped_records_event() -> None:
    log = InMemoryAuditLog()
    registry = default_registry()
    action = registry.propose("send_email", {"to": "a@b.com"})
    log.replay_skipped(action, reason="already executed")
    assert log.events()[-1].event_type is AuditEventType.REPLAY_SKIPPED
