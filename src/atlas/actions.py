"""Action contracts and the approval policy.

This module is the trust boundary of atlas. Three rules are enforced here:

1. **Risk tier is data, not opinion.** A :class:`RiskTier` is attached to an action from the tool
   that owns it (see :mod:`atlas.tools`). The LLM never sets it.
2. **Fail-closed.** :func:`requires_approval` gates anything that is not an explicit, known-safe
   READ — including unknown tiers.
3. **Immutability.** Every record below is ``frozen=True`` so a decision, once made, cannot be
   mutated to authorize something else.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskTier(str, Enum):
    """How dangerous an action is. Declared by tools; never inferred by the model."""

    READ = "read"  # no side effects — safe to auto-run
    WRITE = "write"  # mutates internal state
    SEND = "send"  # communicates externally (email, Slack, …)
    DELETE = "delete"  # destroys data
    PAY = "pay"  # moves money

    @property
    def is_auto_safe(self) -> bool:
        """Only pure reads are safe to run without a human in the loop."""
        return self is RiskTier.READ


# The single source of truth for what may auto-run. Everything else (and anything unknown) is gated.
_AUTO_APPROVED_TIERS: frozenset[RiskTier] = frozenset({RiskTier.READ})


def requires_approval(risk_tier: RiskTier | str | None) -> bool:
    """Return True when an action must be approved by a human before execution.

    Fail-closed: a missing or unrecognized tier always requires approval. This is deliberate — an
    unmapped tool must never slip through as auto-safe.
    """
    if isinstance(risk_tier, RiskTier):
        return risk_tier not in _AUTO_APPROVED_TIERS
    if isinstance(risk_tier, str):
        try:
            return RiskTier(risk_tier) not in _AUTO_APPROVED_TIERS
        except ValueError:
            return True  # unknown string tier => fail-closed
    return True  # None / unexpected type => fail-closed


def _new_action_id() -> str:
    return f"act_{uuid.uuid4().hex[:12]}"


class ProposedAction(BaseModel):
    """An action the planner wants to take. Immutable once created."""

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(default_factory=_new_action_id)
    tool: str = Field(description="Registered tool name to invoke.")
    args: dict[str, Any] = Field(default_factory=dict, description="Validated tool arguments.")
    risk_tier: RiskTier = Field(description="Declared by the tool — not by the LLM.")
    rationale: str = Field(default="", description="Why the agent proposes this action.")

    @property
    def needs_approval(self) -> bool:
        return requires_approval(self.risk_tier)


class ApprovalDecision(BaseModel):
    """A human's decision about exactly one :class:`ProposedAction`.

    The decision is bound to ``action_id`` so it can authorize that action and no other (anti-replay
    / anti-IDOR).
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    approved: bool
    decided_by: str = Field(default="human", description="Principal who made the decision.")


class ActionResult(BaseModel):
    """The outcome of attempting to execute an action. Immutable record for the audit trail."""

    model_config = ConfigDict(frozen=True)

    action_id: str
    tool: str
    ok: bool
    output: Any = None
    error: str | None = None
