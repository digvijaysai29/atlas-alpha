"""Guarded tool execution — idempotency + audit routing for side-effecting actions.

Idempotency is keyed on a durable ``EXECUTED`` audit event for ``action_id``. The side effect
runs inside ``registry.execute`` *before* ``audit.executed()`` appends — so a crash between
provider acceptance and audit persist can still double-send on resume. That window is an accepted
M4.1 limitation (single-writer per ``thread_id``); M4.2+ may add provider idempotency keys or a
pre-claim ledger row. Concurrent executors on the same ``action_id`` are likewise out of scope.
"""

from __future__ import annotations

from atlas.actions import ActionResult, ProposedAction, requires_approval
from atlas.governance.audit import AuditLog, AuditToolContext, _counts_as_executed
from atlas.governance.rbac import Principal
from atlas.tools import ToolRegistry


class GuardedExecutor:
    """Wraps ``ToolRegistry.execute`` with audit-ledger idempotency for gated actions."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def execute_guarded(
        self,
        action: ProposedAction,
        audit: AuditLog,
        principal: Principal,
        *,
        extra: AuditToolContext | None = None,
    ) -> ActionResult:
        if requires_approval(action.risk_tier) and audit.has_executed(action.action_id):
            audit.replay_skipped(action, reason="already executed", extra=extra)
            return self._replay_result(action, audit)
        result = self._registry.execute(action, principal)
        if result.ok:
            audit.executed(result, extra=extra)
        else:
            audit.failed(result, extra=extra)
        return result

    def _replay_result(self, action: ProposedAction, audit: AuditLog) -> ActionResult:
        """Synthetic success so the responder labels replay skips correctly (not 'not approved')."""
        prior_output: dict[str, object] | None = None
        for event in reversed(audit.events()):
            if _counts_as_executed(event) and event.action_id == action.action_id:
                prior_output = {"replay_skipped": True, "prior": event.detail}
                break
        output: dict[str, object] = prior_output or {"replay_skipped": True}
        return ActionResult(action_id=action.action_id, tool=action.tool, ok=True, output=output)
