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

import logging
import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.types import interrupt

from atlas.actions import ActionResult, ApprovalDecision, ProposedAction, requires_approval
from atlas.config import Settings, get_settings
from atlas.governance import AuditLog, PolicyStore
from atlas.governance.audit import AuditToolContext
from atlas.governance.confidence import Source, collect_sources, score_confidence
from atlas.governance.rbac import get_current_principal
from atlas.knowledge.interfaces import Entity, KnowledgeGraph
from atlas.orchestration.responder_llm import ResponderNarrator, make_responder_llm
from atlas.orchestration.state import AgentState
from atlas.execution import GuardedExecutor
from atlas.tools import BaseTool, ToolRegistry

logger = logging.getLogger("atlas.orchestration")

# A planning strategy turns a user request + registry + RBAC-scoped knowledge into proposed actions.
PlanFn = Callable[[str, ToolRegistry, Sequence[Entity]], list[ProposedAction]]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SEND_KEYWORDS = ("email", "send", "notify", "reply", "message")
_SEARCH_KEYWORDS = ("search", "find", "look up", "lookup", "research", "what", "who", "lookup")
_SLACK_KEYWORDS = ("slack",)
_SLACK_CHANNEL_RE = re.compile(r"#([\w-]+)")

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


def _format_kg_context(entities: Sequence[Entity]) -> str:
    """Render retrieved knowledge as one small, bounded block for the LLM system prompt.

    Deliberately dumb (name + a short content snippet per entity) — a grounding hook, not RAG.
    """
    if not entities:
        return ""
    lines = [f"- {entity.name}: {entity.content[:200]}" for entity in entities]
    return "Relevant context you may use (already access-filtered for this user):\n" + "\n".join(
        lines
    )


def heuristic_plan(
    request: str, registry: ToolRegistry, context: Sequence[Entity]
) -> list[ProposedAction]:
    """Deterministic, offline planner. KG-free by design: ``context`` is intentionally ignored so
    the demo and tests stay hermetic (no API key needed).
    """
    del context  # KG-free mode
    text = request.lower()
    actions: list[ProposedAction] = []
    if (
        any(keyword in text for keyword in _SLACK_KEYWORDS)
        and "slack_post" in registry.names()
        and not _EMAIL_RE.search(request)
    ):
        channel_match = _SLACK_CHANNEL_RE.search(request)
        channel = f"#{channel_match.group(1)}" if channel_match else "#general"
        return [
            registry.propose(
                "slack_post",
                {"channel": channel, "text": request},
                rationale="User asked to post to Slack.",
            )
        ]
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


def llm_plan(
    request: str, registry: ToolRegistry, settings: Settings, context: Sequence[Entity]
) -> list[ProposedAction]:
    """LLM-driven planner using Claude tool-calling. Risk tiers still come from the registry.

    Grounds the model with the RBAC-scoped ``context`` (only entities the principal may read).
    """
    from atlas.llm import build_model  # local import: only needed when a key is present

    tool_specs: list[dict[str, Any]] = [
        {
            "name": name,
            "description": registry.get(name).description,
            "input_schema": registry.get(name).ArgsSchema.model_json_schema(),
        }
        for name in registry.names()
    ]
    context_block = _format_kg_context(context)
    system = (
        f"{_PLANNER_SYSTEM_PROMPT}\n\n{context_block}" if context_block else _PLANNER_SYSTEM_PROMPT
    )
    model = build_model(settings).bind_tools(tool_specs)
    ai = model.invoke([("system", system), ("human", request)])

    actions: list[ProposedAction] = []
    for call in getattr(ai, "tool_calls", []) or []:
        # registry.propose validates args and stamps the tool-declared risk tier.
        actions.append(registry.propose(call["name"], call.get("args", {}), rationale="LLM plan."))
    return actions


def default_plan_fn(settings: Settings | None = None) -> PlanFn:
    """Pick the LLM planner when a key is configured, else the offline heuristic."""
    settings = settings or get_settings()
    if settings.has_anthropic_key:
        return lambda request, registry, context: llm_plan(request, registry, settings, context)
    return heuristic_plan


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
def _required_permission_for(action: ProposedAction, tool: BaseTool) -> str | None:
    """Fail-closed resolution of the RBAC permission an action requires (planner + executor).

    Always re-derives from the tool + the action's args via the exact combination ``propose()``
    used, then reconciles with the stamped value:

    - stamped is ``None`` (a pre-M4.8c checkpoint, or an action built outside ``propose()``) →
      the derived value stands in, so ``None`` is never mistaken for "nothing required";
    - stamped differs from derived → the args no longer match the permission they were stamped
      under (post-proposal mutation of the args dict) → raise, and the caller denies.

    Raises on invalid args too — any failure here must deny, never run.
    """
    derived = tool.permission_for(tool.ArgsSchema.model_validate(action.args))
    stamped = action.required_permission
    if stamped is not None and stamped != derived:
        raise ValueError(f"stamped permission {stamped!r} != args-derived {derived!r}")
    return derived


def make_planner_node(
    plan_fn: PlanFn,
    registry: ToolRegistry,
    audit: AuditLog,
    knowledge: KnowledgeGraph,
    policy: PolicyStore,
) -> Callable[[AgentState], dict[str, Any]]:
    def planner_node(state: AgentState) -> dict[str, Any]:
        principal = get_current_principal(state)
        request = _last_user_text(state.get("messages") or [])
        # RBAC-scoped retrieval: only entities this principal may read reach the planner/LLM.
        kg_context = knowledge.query(principal, request, limit=5)
        proposed = plan_fn(request, registry, kg_context)
        # RBAC, deny-early: an action the principal isn't permitted to run is dropped here, so it is
        # never surfaced for human approval. (The executor re-checks as defense-in-depth.)
        authorized: list[ProposedAction] = []
        for action in proposed:
            audit.proposed(action)
            # M4.8c: resolve the (optionally resource-scoped) permission fail-closed. A plan_fn
            # normally stamps it via ToolRegistry.propose, but an action built by hand (custom
            # plan_fn, injected state) may carry None or reference an unknown tool — those must be
            # denied here, before they can ever be surfaced for human approval.
            try:
                tool = registry.get(action.tool)
                required = _required_permission_for(action, tool)
            except Exception:  # noqa: BLE001 - security gate: any failure must deny, not crash
                audit.denied(
                    action, principal.user_id, reason="could not resolve required permission"
                )
                continue
            if not policy.can(principal, required):
                audit.denied(action, principal.user_id, reason=f"missing permission: {required}")
                continue
            authorized.append(action)
        return {"proposed_actions": authorized, "kg_context": list(kg_context)}

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
    registry: ToolRegistry, audit: AuditLog, policy: PolicyStore
) -> Callable[[AgentState], dict[str, Any]]:
    guarded = GuardedExecutor(registry)

    def executor_node(state: AgentState) -> dict[str, Any]:
        principal = get_current_principal(state)
        approved = set(state.get("approved_action_ids") or [])
        results = []
        for action in state.get("proposed_actions") or []:
            try:
                tool = registry.get(action.tool)
            except KeyError:
                # An action for an unregistered tool (injected state / stale checkpoint) is denied,
                # not crashed on — the rest of the turn's actions still execute.
                audit.denied(
                    action,
                    principal.user_id,
                    reason="unknown tool",
                    extra=AuditToolContext(principal=principal.user_id),
                )
                continue
            # Non-secret context (schema id/version, destination host, provider, principal) folded into
            # every audit event for this action so the generated tool action is reconstructable later.
            meta = AuditToolContext(**tool.audit_metadata(), principal=principal.user_id)
            # RBAC re-check (defense-in-depth): never run a tool the principal isn't permitted to use,
            # even if it somehow reached the executor. _required_permission_for re-derives from the
            # args and reconciles with the stamped value, so a None (pre-M4.8c checkpoint) is never
            # read as "nothing required" and args mutated after proposal can't ride a stale grant.
            try:
                required = _required_permission_for(action, tool)
            except Exception:  # noqa: BLE001 - security gate: any failure must deny, not crash
                audit.denied(
                    action,
                    principal.user_id,
                    reason="could not resolve required permission",
                    extra=meta,
                )
                continue
            if not policy.can(principal, required):
                audit.denied(
                    action, principal.user_id, reason=f"missing permission: {required}", extra=meta
                )
                continue
            # The gate, enforced in code: a gated action runs only with a matching approval.
            if requires_approval(action.risk_tier) and action.action_id not in approved:
                audit.skipped(action, reason="not approved", extra=meta)
                continue
            results.append(guarded.execute_guarded(action, audit, principal, extra=meta))
        return {"action_results": results}

    return executor_node


def make_responder_node(
    settings: Settings | None = None,
    *,
    responder_llm: ResponderNarrator | None = None,
) -> Callable[[AgentState], dict[str, Any]]:
    """Build the responder node.

    ``responder_llm`` overrides the settings-based factory (test injection); otherwise
    :func:`~atlas.orchestration.responder_llm.make_responder_llm` decides from ``settings`` — an
    OpenRouter-backed narrator when configured + enabled, ``None`` otherwise. When there is no
    narrator the responder is the deterministic string-formatted summary, byte-for-byte the
    pre-M4.8d behavior (so CI and the eval gate stay hermetic by default).
    """
    settings = settings or get_settings()
    narrator = responder_llm if responder_llm is not None else make_responder_llm(settings)

    def responder_node(state: AgentState) -> dict[str, Any]:
        proposed = state.get("proposed_actions") or []
        results = state.get("action_results") or []
        rejected = set(state.get("rejected_action_ids") or [])
        kg_context = state.get("kg_context") or []
        # Confidence factors execution success + whether the answer was grounded in knowledge.
        confidence = score_confidence(results, kg_context)
        # Structured provenance: tool outputs (from the results) + the RBAC-scoped KG entities used.
        sources = collect_sources(results, kg_context)
        # The deterministic summary is always computed first (cheap, pure) — it is both the default
        # responder text AND the fallback if the LLM narrator fails below. All authorization-relevant
        # decisions (risk tier, RBAC, approval) are already final by this point; the narrator below
        # only rephrases them, it never re-decides anything.
        summary = _summarize(proposed, results, rejected)
        if narrator is not None:
            request = _last_user_text(state.get("messages") or [])
            facts = _facts_block(summary, sources)
            try:
                summary = narrator.respond(request, facts)
            except Exception:
                logger.exception("Responder LLM failed; falling back to the deterministic summary")
        return {
            "messages": [AIMessage(content=summary)],
            "confidence": confidence,
            "sources": sources,
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


def _facts_block(summary: str, sources: Sequence[Source]) -> str:
    """Render the turn's already-decided facts as plain text for the responder LLM prompt (M4.8d).

    Reuses the same deterministic summary :func:`_summarize` already produced — the LLM only
    rephrases what already happened; it never decides or adds to it. ``sources`` is the RBAC-filtered
    provenance list, already safe to surface.
    """
    lines = [summary]
    if sources:
        lines.append("Sources used:")
        lines.extend(f"- {source.label or source.ref}" for source in sources)
    return "\n".join(lines)


def _summarize(
    proposed: list[ProposedAction],
    results: list[ActionResult],
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
        elif isinstance(result.output, dict) and result.output.get("replay_skipped"):
            lines.append(f"- Replay skipped (already executed): {action.tool}")
        elif result.ok:
            lines.append(f"- Executed: {action.tool} -> {result.output}")
        else:
            lines.append(f"- Failed: {action.tool} -> {result.error}")
    return "Here is what I did:\n" + "\n".join(lines)
