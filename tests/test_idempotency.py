"""Idempotent guarded execution — double-send prevention (M4.1)."""

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.execution import GuardedExecutor
from atlas.governance import AuditEventType, InMemoryAuditLog, InMemoryPolicyStore
from atlas.governance.rbac import Principal
from atlas.orchestration.nodes import _summarize, make_executor_node
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry
from atlas.integrations.gmail import FakeGmailSender
from tests.helpers import FakeEmailSender, FakeSlackSender, offline_registry

_TEST_PRINCIPAL = Principal(user_id="test", roles=("member",), org_id="org1")


def _approved_send(registry: ToolRegistry) -> ProposedAction:
    action = registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})
    return action


def _approved_slack(registry: ToolRegistry) -> ProposedAction:
    return registry.propose("slack_post", {"channel": "#general", "text": "hi"})


def test_double_execute_calls_sender_once_and_replay_skips() -> None:
    sender = FakeEmailSender()
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_send(registry)

    first = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)
    second = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)

    assert sender.call_count == 1
    assert first.ok is True
    assert second.ok is True
    assert isinstance(second.output, dict) and second.output.get("replay_skipped") is True
    types = [e.event_type for e in audit.events()]
    assert types.count(AuditEventType.EXECUTED) == 1
    assert AuditEventType.REPLAY_SKIPPED in types


def test_failed_send_is_retryable() -> None:
    sender = FakeEmailSender(fail=True)
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_send(registry)

    first = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)
    sender.fail = False
    second = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)

    assert first.ok is False
    assert second.ok is True
    assert sender.call_count == 2
    types = [e.event_type for e in audit.events()]
    assert AuditEventType.FAILED in types
    assert types.count(AuditEventType.EXECUTED) == 1


def test_unguarded_double_execute_would_call_twice() -> None:
    """Negative control: without the guard, the sender would be invoked twice."""
    sender = FakeEmailSender()
    registry = offline_registry(sender)
    action = _approved_send(registry)
    registry.execute(action, _TEST_PRINCIPAL)
    registry.execute(action, _TEST_PRINCIPAL)
    assert sender.call_count == 2


def test_executor_node_double_invocation_skips_second_send() -> None:
    """Orchestration layer: make_executor_node shares GuardedExecutor idempotency."""
    sender = FakeEmailSender()
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    policy = InMemoryPolicyStore()
    executor = make_executor_node(registry, audit, policy)
    action = _approved_send(registry)
    audit.proposed(action)
    principal = Principal(user_id="alice", roles=("member",))
    state = initial_state("email a@b.com", principal=principal)
    state["proposed_actions"] = [action]
    state["approved_action_ids"] = [action.action_id]

    first = executor(state)
    second = executor(state)

    assert sender.call_count == 1
    assert first["action_results"][0].ok is True
    replay = second["action_results"][0]
    assert isinstance(replay.output, dict) and replay.output.get("replay_skipped") is True
    assert AuditEventType.REPLAY_SKIPPED in [e.event_type for e in audit.events()]


def test_summarize_labels_replay_skip() -> None:
    sender = FakeEmailSender()
    registry = offline_registry(sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_send(registry)

    first = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)
    replay = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)

    summary = _summarize([action], [first, replay], rejected=set())
    assert "Replay skipped (already executed)" in summary
    assert "Skipped (not approved)" not in summary


def test_double_slack_execute_calls_sender_once_and_replay_skips() -> None:
    sender = FakeSlackSender()
    registry = offline_registry(slack_sender=sender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_slack(registry)

    first = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)
    second = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)

    assert sender.call_count == 1
    assert first.ok is True
    assert second.ok is True
    assert isinstance(second.output, dict) and second.output.get("replay_skipped") is True
    types = [e.event_type for e in audit.events()]
    assert types.count(AuditEventType.EXECUTED) == 1
    assert AuditEventType.REPLAY_SKIPPED in types


def _approved_gmail(registry: ToolRegistry) -> ProposedAction:
    return registry.propose("gmail_send", {"to": "a@b.com", "subject": "hi", "body": "x"})


def test_double_gmail_execute_calls_sender_once_and_replay_skips() -> None:
    from datetime import UTC, datetime, timedelta

    from atlas.governance.credentials import (
        InMemoryCredentialVault,
        OAuthProvider,
        StoredCredential,
    )
    from atlas.integrations.oauth import GOOGLE_GMAIL_SEND, build_credential_resolver

    vault = InMemoryCredentialVault()
    vault.put(
        _TEST_PRINCIPAL,
        OAuthProvider.GOOGLE,
        StoredCredential(
            provider=OAuthProvider.GOOGLE,
            scopes=(GOOGLE_GMAIL_SEND,),
            access_token="tok",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    resolver = build_credential_resolver(vault, Settings())
    registry = offline_registry(credential_resolver=resolver)
    gmail = registry.get("gmail_send")._sender
    assert isinstance(gmail, FakeGmailSender)
    audit = InMemoryAuditLog()
    guarded = GuardedExecutor(registry)
    action = _approved_gmail(registry)

    first = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)
    second = guarded.execute_guarded(action, audit, _TEST_PRINCIPAL)

    assert gmail.call_count == 1
    assert first.ok is True
    assert second.ok is True
    assert isinstance(second.output, dict) and second.output.get("replay_skipped") is True
