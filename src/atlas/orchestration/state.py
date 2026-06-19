"""Graph state for the orchestration layer.

State is a LangGraph ``TypedDict`` of channels. Only ``messages`` uses a reducer (``add_messages``);
the rest are last-write channels. The *values* held in those channels are immutable Pydantic models
(see :mod:`atlas.actions`), and nodes return **new** partial updates rather than mutating state.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage, HumanMessage
from langgraph.graph.message import add_messages

from atlas.actions import ActionResult, ProposedAction
from atlas.governance.rbac import Principal


class AgentState(TypedDict, total=False):
    """The working memory of a single agent thread."""

    # Conversation. ``add_messages`` appends/merges rather than overwriting.
    messages: Annotated[list[AnyMessage], add_messages]

    # The identity this run executes as. RBAC checks are scoped to this principal.
    principal: Principal | None

    # Actions the planner proposed this turn (each carries its tool-declared risk tier).
    proposed_actions: list[ProposedAction]

    # Decisions, bound to action ids. Only ids present in ``approved_action_ids`` may execute.
    approved_action_ids: list[str]
    rejected_action_ids: list[str]

    # Execution outputs and provenance for the final answer.
    action_results: list[ActionResult]
    sources: list[str]
    confidence: float | None


def initial_state(user_message: str, principal: Principal | None = None) -> AgentState:
    """Build a fresh state for a new user request.

    ``principal`` defaults to :meth:`Principal.anonymous` (fail-closed: no roles, no permissions).
    """
    return {
        "messages": [HumanMessage(content=user_message)],
        "principal": principal or Principal.anonymous(),
        "proposed_actions": [],
        "approved_action_ids": [],
        "rejected_action_ids": [],
        "action_results": [],
        "sources": [],
        "confidence": None,
    }
