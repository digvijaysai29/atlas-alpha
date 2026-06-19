"""Golden-trace inputs as data: principals and scripted, deterministic planners.

These mirror the fixtures in ``tests/`` (a ``send_email`` plan, a ``search`` plan, an empty plan)
so the gate enforces the same security behavior the unit tests assert — but framed as named, scored
golden traces a CI gate can track over time. Everything here is offline and deterministic: no API
key, no network, no model call.
"""

from __future__ import annotations

from collections.abc import Sequence

from atlas.actions import ProposedAction
from atlas.governance.rbac import Principal
from atlas.knowledge.interfaces import Entity
from atlas.tools import ToolRegistry

# A principal that holds "tool:send" (+ kg:read:org/personal) — exercises the APPROVAL gate.
MEMBER = Principal(user_id="alice", roles=("member",))
# A principal lacking "tool:send" (and kg:read:org) — exercises the RBAC / IDOR guards.
GUEST = Principal(user_id="bob", roles=("guest",))


def send_email_plan(
    _request: str, registry: ToolRegistry, _context: Sequence[Entity]
) -> list[ProposedAction]:
    """Propose a single gated ``send_email`` (RiskTier.SEND → requires approval)."""
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def search_plan(
    _request: str, registry: ToolRegistry, _context: Sequence[Entity]
) -> list[ProposedAction]:
    """Propose a single auto-safe ``search`` (RiskTier.READ → runs without approval)."""
    return [registry.propose("search", {"query": "quarterly numbers"})]


def empty_plan(
    _request: str, _registry: ToolRegistry, _context: Sequence[Entity]
) -> list[ProposedAction]:
    """Propose nothing — routes straight to the responder (exercises grounded vs ungrounded)."""
    return []
