"""Integration layer: the Tool protocol, the registry, and mock tools.

A tool **declares its own** :class:`~atlas.actions.RiskTier`. The registry is the single place that
turns "the agent wants to call tool X with args Y" into a typed, risk-tagged
:class:`~atlas.actions.ProposedAction`. Because the tier is copied from the tool here — never from
model output — the LLM cannot relabel a dangerous action as safe.
"""

from __future__ import annotations

import abc
from typing import Any

from pydantic import BaseModel, Field

from atlas.actions import ActionResult, ProposedAction, RiskTier


class BaseTool(abc.ABC):
    """Contract every tool must satisfy.

    Subclasses set ``name``, ``description``, ``risk_tier`` and ``ArgsSchema`` (a Pydantic model used
    to validate arguments at the boundary), and implement :meth:`run`.
    """

    name: str
    description: str
    risk_tier: RiskTier
    ArgsSchema: type[BaseModel]

    @abc.abstractmethod
    def run(self, args: BaseModel) -> Any:
        """Execute the tool with already-validated arguments and return its output."""
        raise NotImplementedError


class ToolRegistry:
    """Holds the available tools and mediates proposing/executing them."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def names(self) -> list[str]:
        return sorted(self._tools)

    def propose(self, tool_name: str, args: dict[str, Any], rationale: str = "") -> ProposedAction:
        """Build a risk-tagged :class:`ProposedAction`, validating args against the tool's schema.

        The ``risk_tier`` is taken from the tool definition — this is the security invariant.
        """
        tool = self.get(tool_name)
        validated = tool.ArgsSchema.model_validate(args)  # raises on invalid input
        return ProposedAction(
            tool=tool.name,
            args=validated.model_dump(),
            risk_tier=tool.risk_tier,
            rationale=rationale,
        )

    def execute(self, action: ProposedAction) -> ActionResult:
        """Run a single action, capturing success or failure as an immutable result.

        Callers (the executor node) are responsible for confirming the action is authorized *before*
        calling this. Errors are caught and surfaced — never silently swallowed.
        """
        try:
            tool = self.get(action.tool)
            args = tool.ArgsSchema.model_validate(action.args)
            output = tool.run(args)
            return ActionResult(
                action_id=action.action_id, tool=action.tool, ok=True, output=output
            )
        except Exception as exc:  # noqa: BLE001 - report failures, never silently swallow
            return ActionResult(
                action_id=action.action_id,
                tool=action.tool,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )


# ---------------------------------------------------------------------------
# Mock tools (M1). Real integrations (Gmail/Slack/Jira) arrive in later milestones.
# ---------------------------------------------------------------------------


class _SearchArgs(BaseModel):
    query: str = Field(min_length=1, description="What to search for.")


class SearchTool(BaseTool):
    """A read-only knowledge lookup. Safe to auto-run (no side effects)."""

    name = "search"
    description = "Search the knowledge base for information. Read-only."
    risk_tier = RiskTier.READ
    ArgsSchema = _SearchArgs

    def run(self, args: BaseModel) -> Any:
        if not isinstance(args, _SearchArgs):
            raise TypeError(f"expected _SearchArgs, got {type(args).__name__}")
        # Mock result — a real implementation would query the Knowledge Graph (RBAC-scoped).
        return {
            "query": args.query,
            "results": [f"(mock) top result for {args.query!r}"],
            "source": "mock-knowledge-base",
        }


class _SendEmailArgs(BaseModel):
    to: str = Field(min_length=3, description="Recipient address.")
    subject: str = Field(default="", description="Email subject.")
    body: str = Field(default="", description="Email body.")


class SendEmailTool(BaseTool):
    """Sends an email — an external, irreversible side effect. Must be gated."""

    name = "send_email"
    description = "Send an email to a recipient. Irreversible external action."
    risk_tier = RiskTier.SEND
    ArgsSchema = _SendEmailArgs

    def run(self, args: BaseModel) -> Any:
        if not isinstance(args, _SendEmailArgs):
            raise TypeError(f"expected _SendEmailArgs, got {type(args).__name__}")
        # Mock send — a real implementation would call the email provider here.
        return {"status": "sent", "to": args.to, "subject": args.subject}


def default_registry() -> ToolRegistry:
    """A registry pre-loaded with the M1 mock tools."""
    registry = ToolRegistry()
    registry.register(SearchTool())
    registry.register(SendEmailTool())
    return registry
