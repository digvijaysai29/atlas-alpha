"""The four orchestration nodes plus planning strategies and routing.

Flow: ``planner → (approval / interrupt) → executor → responder``.

Security invariants enforced here:

- The **planner** assigns risk via the registry, never from model output.
- The **approval** node binds each decision to a specific ``action_id`` and ignores decisions for
  unknown ids.
- The **executor** re-checks the policy and a matching approval *before* running any action — the
  gate lives in code, not merely in the graph's shape.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.types import interrupt

from atlas.actions import ApprovalDecision, ProposedAction, RiskTier, requires_approval
from atlas.config import Settings, get_settings
from atlas.governance import AuditLog
from atlas.orchestration.state import AgentState
from atlas.tools import ToolRegistry

# A planning strategy turns a user request + registry into proposed actions.
PlanFn = Callable[[str, ToolRegistry], list[ProposedAction]]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SEND_KEYWORDS = ("email", "send", "notify", "reply", "message")
_SEARCH_KEYWORDS = ("search", "find", "look up", "lookup", "research", "what", "who", "lookup")

_PLANNER_SYSTEM_PROMPT = (
    "You are atlas, an enterprise agent. Decide which tools to call to satisfy the user. "
    "Only call tools that are necessary. Never attempt to bypass approval for sensitive actions."
)


# ---------------------------------------------------------------------------
# Planning strategies
# ---------------------------------------------------------------------------
def _last_user_text(messages: Iterable[AnyMessage]) -> str:
    text = ""
    for message in messages:
        if message.type == "human":
            text = getattr(message, "text", None) or str(message.content)
    return text


def heuristic_plan(request: str, registry: ToolRegistry) -> list[ProposedAction]:
    """Deterministic, offline planner. Keeps the demo and tests hermetic (no API key needed)."""
    text = request.lower()
    actions: list[ProposedAction] = []
    if any(keyword in text for keyword in _SEND_KEYWORDS) and "send_email" in registry.names():
        recipient = _EMAIL_RE.search(request)
        actions.append(
            registry.propose(
                "send_email",
                {
                    "to": recipient.group(0) if recipient else "recipient@example.com",
                    "subject": "Message from atlas",
                    "body": request,
                },
                rationale="User asked to send a message.",
            )
        )
    if any(keyword in text for keyword in _SEARCH_KEYWORDS) and "search" in registry.names():
        actions.append(
            registry.propose(
                "search",
                {"query": request},
                rationale="User asked to find information.",
            )
        )
    return actions


def llm_plan(request: str, registry: ToolRegistry, settings: Settings) -> list[ProposedAction]:
    """LLM-driven planner using Claude tool-calling. Risk tiers still come from the registry."""
    from atlas.llm import build_model  # local import: only needed when a key is present

    tool_specs: list[dict[str, Any]] = [
        {
            "name": name,
            "description": registry.get(name).description,
            "input_schema": registry.get(name).ArgsSchema.model_json_schema(),
        }
        for name in registry.names()
    ]
    model = build_model(settings).bind_tools(tool_specs)
    ai = model.invoke([("system", _PLANNER_SYSTEM_PROMPT), ("human", request)])

    actions: list[ProposedAction] = []
    for call in getattr(ai, "tool_calls", []) or []:
        # registry.propose validates args and stamps the tool-declared risk tier.
        actions.append(registry.propose(call["name"], call.get("args", {}), rationale="LLM plan."))
    return actions


def default_plan_fn(settings: Settings | None = None) -> PlanFn:
    """Pick the LLM planner when a key is configured, else the offline heuristic."""
    settings = settings or get_settings()
    if settings.has_anthropic_key:
        return lambda request, registry: llm_plan(request, registry, settings)
    return heuristic_plan


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
def make_planner_node(
    plan_fn: PlanFn, registry: ToolRegistry, audit: AuditLog
) -> Callable[[AgentState], dict[str, Any]]:
    def planner_node(state: AgentState) -> dict[str, Any]:
        request = _last_user_text(state.get("messages") or [])
        proposed = plan_fn(request, registry)
        for action in proposed:
            audit.proposed(action)
        return {"proposed_actions": proposed}

    return planner_node


def make_approval_node(audit: AuditLog) -> Callable[[AgentState], dict[str, Any]]:
    def approval_node(state: AgentState) -> dict[str, Any]:
        gated = [a for a in (state.get("proposed_actions") or []) if a.needs_approval]
        valid_ids = {a.action_id for a in gated}

        # Pause the graph durably and surface the pending actions for a human to review.
        raw_decision = interrupt(
            {
                "type": "approval_request",
                "question": "Approve these actions?",
                "pending_actions": [a.model_dump(mode="json") for a in gated],
            }
        )

        decisions = _parse_decisions(raw_decision, valid_ids)
        approved: list[str] = []
        rejected: list[str] = []
        for decision in decisions:
            audit.decided(decision)
            (approved if decision.approved else rejected).append(decision.action_id)
        return {"approved_action_ids": approved, "rejected_action_ids": rejected}

    return approval_node


def make_executor_node(
    registry: ToolRegistry, audit: AuditLog
) -> Callable[[AgentState], dict[str, Any]]:
    def executor_node(state: AgentState) -> dict[str, Any]:
        approved = set(state.get("approved_action_ids") or [])
        results = []
        sources = list(state.get("sources") or [])
        for action in state.get("proposed_actions") or []:
            # The gate, enforced in code: a gated action runs only with a matching approval.
            if requires_approval(action.risk_tier) and action.action_id not in approved:
                audit.skipped(action, reason="not approved")
                continue
            result = registry.execute(action)
            audit.executed(result)
            results.append(result)
            if action.risk_tier is RiskTier.READ and result.ok and isinstance(result.output, dict):
                source = result.output.get("source")
                if source:
                    sources.append(str(source))
        return {"action_results": results, "sources": sources}

    return executor_node


def make_responder_node() -> Callable[[AgentState], dict[str, Any]]:
    def responder_node(state: AgentState) -> dict[str, Any]:
        proposed = state.get("proposed_actions") or []
        results = state.get("action_results") or []
        rejected = set(state.get("rejected_action_ids") or [])
        confidence = _confidence(results)
        summary = _summarize(proposed, results, rejected)
        return {
            "messages": [AIMessage(content=summary)],
            "confidence": confidence,
            "sources": state.get("sources") or [],
        }

    return responder_node


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
def route_after_planner(state: AgentState) -> str:
    proposed = state.get("proposed_actions") or []
    if any(action.needs_approval for action in proposed):
        return "approval"
    if proposed:
        return "executor"
    return "responder"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_decisions(raw: Any, valid_ids: set[str]) -> list[ApprovalDecision]:
    """Normalize a resume payload into decisions, keeping only known action ids (anti-replay).

    Accepted shapes:
      - ``True`` / ``False``            -> apply to all gated actions
      - ``[{"action_id", "approved"}]`` -> explicit per-action decisions
      - ``{action_id: bool}``           -> mapping of decisions
      - ``{"approved_ids": [...], "rejected_ids": [...]}``
    """
    if isinstance(raw, bool):
        return [ApprovalDecision(action_id=aid, approved=raw) for aid in valid_ids]

    decisions: list[ApprovalDecision] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("action_id") in valid_ids:
                decisions.append(
                    ApprovalDecision(
                        action_id=str(item["action_id"]),
                        approved=bool(item.get("approved", False)),
                        decided_by=str(item.get("decided_by", "human")),
                    )
                )
    elif isinstance(raw, dict) and ("approved_ids" in raw or "rejected_ids" in raw):
        for aid in raw.get("approved_ids", []):
            if aid in valid_ids:
                decisions.append(ApprovalDecision(action_id=str(aid), approved=True))
        for aid in raw.get("rejected_ids", []):
            if aid in valid_ids:
                decisions.append(ApprovalDecision(action_id=str(aid), approved=False))
    elif isinstance(raw, dict):
        for aid, approved in raw.items():
            if aid in valid_ids:
                decisions.append(ApprovalDecision(action_id=str(aid), approved=bool(approved)))
    return decisions


def _confidence(results: list[Any]) -> float:
    """Placeholder confidence: fraction of actions that executed successfully (matured in M2)."""
    if not results:
        return 0.9  # answered without needing actions
    ok = sum(1 for result in results if result.ok)
    return round(ok / len(results), 2)


def _summarize(
    proposed: list[ProposedAction],
    results: list[Any],
    rejected: set[str],
) -> str:
    if not proposed:
        return "I did not need to take any actions to answer that."
    lines: list[str] = []
    by_id = {result.action_id: result for result in results}
    for action in proposed:
        result = by_id.get(action.action_id)
        if result is None:
            verb = "Rejected" if action.action_id in rejected else "Skipped (not approved)"
            lines.append(f"- {verb}: {action.tool} ({action.risk_tier.value})")
        elif result.ok:
            lines.append(f"- Executed: {action.tool} -> {result.output}")
        else:
            lines.append(f"- Failed: {action.tool} -> {result.error}")
    return "Here is what I did:\n" + "\n".join(lines)
