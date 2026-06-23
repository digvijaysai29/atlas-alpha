"""Integration layer: the Tool protocol, the registry, and mock tools.

A tool **declares its own** :class:`~atlas.actions.RiskTier`. The registry is the single place that
turns "the agent wants to call tool X with args Y" into a typed, risk-tagged
:class:`~atlas.actions.ProposedAction`. Because the tier is copied from the tool here — never from
model output — the LLM cannot relabel a dangerous action as safe.
"""

from __future__ import annotations

import abc
import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

from atlas.actions import ActionResult, ProposedAction, RiskTier
from atlas.config import Settings, get_settings
from atlas.integrations.email import (
    EmailMessage,
    EmailSender,
    FakeEmailSender,
    build_email_sender,
)
from atlas.integrations.slack import (
    SLACK_MAX_TEXT_CHARS,
    FakeSlackSender,
    SlackMessage,
    SlackSender,
    build_slack_sender,
)

logger = logging.getLogger("atlas.tools")


class BaseTool(abc.ABC):
    """Contract every tool must satisfy.

    Subclasses set ``name``, ``description``, ``risk_tier`` and ``ArgsSchema`` (a Pydantic model used
    to validate arguments at the boundary), and implement :meth:`run`. A tool may optionally declare
    ``required_permission`` — an RBAC capability string the calling principal must hold (default
    ``None`` = no special permission required). Raw string for now; a richer ``ToolPermission`` model
    is an M3/M4 placeholder.
    """

    name: str
    description: str
    risk_tier: RiskTier
    ArgsSchema: type[BaseModel]
    required_permission: str | None = None

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
    required_permission = "tool:send"  # RBAC: only principals granted "tool:send" may use this
    ArgsSchema = _SendEmailArgs

    def __init__(self, sender: EmailSender | None = None) -> None:
        self._sender = sender

    def run(self, args: BaseModel) -> Any:
        if not isinstance(args, _SendEmailArgs):
            raise TypeError(f"expected _SendEmailArgs, got {type(args).__name__}")
        if self._sender is None:
            raise RuntimeError("email not configured")
        message = EmailMessage(to=args.to, subject=args.subject, text=args.body or None)
        return self._sender.send(message)


class _SlackPostArgs(BaseModel):
    channel: str = Field(min_length=1, description="Slack channel ID or name.")
    text: str = Field(
        min_length=1,
        max_length=SLACK_MAX_TEXT_CHARS,
        description="Message text.",
    )

    @field_validator("channel")
    @classmethod
    def reject_non_channel_targets(cls, value: str) -> str:
        stripped = value.strip()
        if stripped.startswith("@"):
            raise ValueError(
                "channel must be a channel name or ID (C…/G…/#name); "
                "@-mentions are not allowed for slack_post"
            )
        # Slack user (U…) and DM conversation (D…) IDs open DMs, not channel posts.
        if stripped[:1].upper() in {"U", "D"} and len(stripped) > 1:
            raise ValueError(
                "channel must be a channel name or ID (C…/G…/#name); "
                "user/DM targets are not allowed for slack_post"
            )
        return value


class SlackPostTool(BaseTool):
    """Posts to Slack — an external, irreversible side effect. Must be gated."""

    name = "slack_post"
    description = "Post a message to a Slack channel. Irreversible external action."
    risk_tier = RiskTier.SEND
    required_permission = "tool:slack:post"
    ArgsSchema = _SlackPostArgs

    def __init__(self, sender: SlackSender | None = None) -> None:
        self._sender = sender

    def run(self, args: BaseModel) -> Any:
        if not isinstance(args, _SlackPostArgs):
            raise TypeError(f"expected _SlackPostArgs, got {type(args).__name__}")
        if self._sender is None:
            raise RuntimeError("slack not configured")
        message = SlackMessage(channel=args.channel, text=args.text)
        return self._sender.post(message)


def offline_registry(
    sender: EmailSender | None = None,
    slack_sender: SlackSender | None = None,
) -> ToolRegistry:
    """Registry with fake senders so offline demos/tests never hit Resend or Slack."""
    registry = ToolRegistry()
    registry.register(SearchTool())
    registry.register(SendEmailTool(sender=sender or FakeEmailSender()))
    registry.register(SlackPostTool(sender=slack_sender or FakeSlackSender()))
    return registry


def _resolve_email_sender(settings: Settings) -> EmailSender | None:
    """Return a real sender only when email is configured **and** audit is durable (Postgres)."""
    if not settings.email_configured:
        return None
    if settings.database_url is None:
        logger.warning(
            "RESEND_API_KEY/ATLAS_EMAIL_FROM are set but DATABASE_URL is unset — real send_email "
            "is disabled (in-memory audit cannot enforce idempotency across restarts). "
            "Set DATABASE_URL for durable audit or pass offline_registry() in demos/tests."
        )
        return None
    return build_email_sender(settings)


def _resolve_slack_sender(settings: Settings) -> SlackSender | None:
    """Return a real sender only when Slack is configured **and** audit is durable (Postgres)."""
    if not settings.slack_configured:
        return None
    if settings.database_url is None:
        logger.warning(
            "SLACK_BOT_TOKEN is set but DATABASE_URL is unset — real slack_post "
            "is disabled (in-memory audit cannot enforce idempotency across restarts). "
            "Set DATABASE_URL for durable audit or pass offline_registry() in demos/tests."
        )
        return None
    return build_slack_sender(settings)


def default_registry(settings: Settings | None = None) -> ToolRegistry:
    """A registry pre-loaded with the standard tools.

    Live Resend send is enabled only when ``DATABASE_URL`` (durable audit) and Resend creds are set.
    Live Slack post is enabled only when ``DATABASE_URL`` and ``SLACK_BOT_TOKEN`` are set.
    """
    settings = settings or get_settings()
    sender = _resolve_email_sender(settings)
    slack_sender = _resolve_slack_sender(settings)
    registry = ToolRegistry()
    registry.register(SearchTool())
    registry.register(SendEmailTool(sender=sender))
    registry.register(SlackPostTool(sender=slack_sender))
    return registry
