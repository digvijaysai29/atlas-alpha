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
from atlas.governance.credentials import CredentialResolver, OAuthProvider
from atlas.governance.rbac import Principal
from atlas.integrations.calendar import (
    CalendarClient,
    CalendarEvent,
    FakeCalendarClient,
    GoogleCalendarClient,
)
from atlas.integrations.email import (
    EmailMessage,
    EmailSender,
    FakeEmailSender,
    build_email_sender,
)
from atlas.integrations.gmail import FakeGmailSender, GmailApiSender, GmailMessage, GmailSender
from atlas.integrations.oauth import (
    GOOGLE_CALENDAR_EVENTS,
    GOOGLE_GMAIL_SEND,
    SLACK_USER_CHAT_WRITE,
)
from atlas.integrations.slack import (
    SLACK_MAX_TEXT_CHARS,
    FakeSlackSender,
    SlackMessage,
    SlackSender,
    build_slack_sender,
)
from atlas.integrations.slack_user import (
    FakeSlackUserSender,
    SlackUserApiSender,
    SlackUserMessage,
    SlackUserSender,
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
    def run(self, args: BaseModel, *, principal: Principal) -> Any:
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

    def execute(self, action: ProposedAction, principal: Principal) -> ActionResult:
        """Run a single action, capturing success or failure as an immutable result.

        Callers (the executor node) are responsible for confirming the action is authorized *before*
        calling this. Errors are caught and surfaced — never silently swallowed.
        """
        try:
            tool = self.get(action.tool)
            args = tool.ArgsSchema.model_validate(action.args)
            output = tool.run(args, principal=principal)
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

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        del principal
        if not isinstance(args, _SearchArgs):
            raise TypeError(f"expected _SearchArgs, got {type(args).__name__}")
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
    required_permission = "tool:send"
    ArgsSchema = _SendEmailArgs

    def __init__(self, sender: EmailSender | None = None) -> None:
        self._sender = sender

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        del principal
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

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        del principal
        if not isinstance(args, _SlackPostArgs):
            raise TypeError(f"expected _SlackPostArgs, got {type(args).__name__}")
        if self._sender is None:
            raise RuntimeError("slack not configured")
        message = SlackMessage(channel=args.channel, text=args.text)
        return self._sender.post(message)


class _GmailSendArgs(BaseModel):
    to: str = Field(min_length=3, description="Recipient address.")
    subject: str = Field(default="", description="Email subject.")
    body: str = Field(default="", description="Email body.")


class GmailSendTool(BaseTool):
    """Send email via the user's connected Gmail account."""

    name = "gmail_send"
    description = "Send an email as the authenticated user via Gmail. Irreversible external action."
    risk_tier = RiskTier.SEND
    required_permission = "tool:gmail:send"
    ArgsSchema = _GmailSendArgs

    def __init__(
        self,
        *,
        sender: GmailSender | None = None,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self._sender = sender
        self._credential_resolver = credential_resolver

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        if not isinstance(args, _GmailSendArgs):
            raise TypeError(f"expected _GmailSendArgs, got {type(args).__name__}")
        if self._sender is None or self._credential_resolver is None:
            raise RuntimeError("gmail not configured")
        token = self._credential_resolver.get_access_token(
            principal, OAuthProvider.GOOGLE, frozenset({GOOGLE_GMAIL_SEND})
        )
        message = GmailMessage(to=args.to, subject=args.subject, text=args.body or None)
        return self._sender.send(message, access_token=token)


class _CalendarCreateEventArgs(BaseModel):
    summary: str = Field(min_length=1, description="Event title.")
    start: str = Field(min_length=1, description="ISO-8601 start datetime.")
    end: str = Field(min_length=1, description="ISO-8601 end datetime.")
    description: str = Field(default="", description="Event description.")
    location: str = Field(default="", description="Event location.")
    timezone: str = Field(default="UTC", description="IANA timezone for start/end.")


class CalendarCreateEventTool(BaseTool):
    """Create a calendar event on the user's connected Google Calendar."""

    name = "calendar_create_event"
    description = "Create a calendar event as the authenticated user. Irreversible external action."
    risk_tier = RiskTier.SEND
    required_permission = "tool:calendar:write"
    ArgsSchema = _CalendarCreateEventArgs

    def __init__(
        self,
        *,
        client: CalendarClient | None = None,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self._client = client
        self._credential_resolver = credential_resolver

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        if not isinstance(args, _CalendarCreateEventArgs):
            raise TypeError(f"expected _CalendarCreateEventArgs, got {type(args).__name__}")
        if self._client is None or self._credential_resolver is None:
            raise RuntimeError("calendar not configured")
        token = self._credential_resolver.get_access_token(
            principal, OAuthProvider.GOOGLE, frozenset({GOOGLE_CALENDAR_EVENTS})
        )
        event = CalendarEvent(
            summary=args.summary,
            start=args.start,
            end=args.end,
            description=args.description,
            location=args.location,
            timezone=args.timezone,
        )
        return self._client.create_event(event, access_token=token)


class _SlackPostAsUserArgs(BaseModel):
    channel: str = Field(min_length=1, description="Slack channel ID or name.")
    text: str = Field(
        min_length=1,
        max_length=SLACK_MAX_TEXT_CHARS,
        description="Message text.",
    )


class SlackPostAsUserTool(BaseTool):
    """Post to Slack as the authenticated user (user OAuth token)."""

    name = "slack_post_as_user"
    description = "Post a Slack message as the authenticated user. Irreversible external action."
    risk_tier = RiskTier.SEND
    required_permission = "tool:slack:post_as_user"
    ArgsSchema = _SlackPostAsUserArgs

    def __init__(
        self,
        *,
        sender: SlackUserSender | None = None,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self._sender = sender
        self._credential_resolver = credential_resolver

    def run(self, args: BaseModel, *, principal: Principal) -> Any:
        if not isinstance(args, _SlackPostAsUserArgs):
            raise TypeError(f"expected _SlackPostAsUserArgs, got {type(args).__name__}")
        if self._sender is None or self._credential_resolver is None:
            raise RuntimeError("slack user post not configured")
        token = self._credential_resolver.get_access_token(
            principal, OAuthProvider.SLACK, frozenset({SLACK_USER_CHAT_WRITE})
        )
        message = SlackUserMessage(channel=args.channel, text=args.text)
        return self._sender.post(message, access_token=token)


def _register_oauth_tools(
    registry: ToolRegistry,
    credential_resolver: CredentialResolver | None,
    *,
    gmail_sender: GmailSender | None = None,
    calendar_client: CalendarClient | None = None,
    slack_user_sender: SlackUserSender | None = None,
) -> None:
    registry.register(
        GmailSendTool(
            sender=gmail_sender,
            credential_resolver=credential_resolver,
        )
    )
    registry.register(
        CalendarCreateEventTool(
            client=calendar_client,
            credential_resolver=credential_resolver,
        )
    )
    registry.register(
        SlackPostAsUserTool(
            sender=slack_user_sender,
            credential_resolver=credential_resolver,
        )
    )


def offline_registry(
    sender: EmailSender | None = None,
    slack_sender: SlackSender | None = None,
    credential_resolver: CredentialResolver | None = None,
) -> ToolRegistry:
    """Registry with fake senders so offline demos/tests never hit external APIs."""
    from atlas.governance.credentials import InMemoryCredentialVault
    from atlas.integrations.oauth import build_credential_resolver

    registry = ToolRegistry()
    resolver = credential_resolver or build_credential_resolver(
        InMemoryCredentialVault(), Settings()
    )
    registry.register(SearchTool())
    registry.register(SendEmailTool(sender=sender or FakeEmailSender()))
    registry.register(SlackPostTool(sender=slack_sender or FakeSlackSender()))
    _register_oauth_tools(
        registry,
        resolver,
        gmail_sender=FakeGmailSender(),
        calendar_client=FakeCalendarClient(),
        slack_user_sender=FakeSlackUserSender(),
    )
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


def _resolve_oauth_tools(
    settings: Settings,
    credential_resolver: CredentialResolver | None,
) -> tuple[
    GmailSender | None, CalendarClient | None, SlackUserSender | None, CredentialResolver | None
]:
    """Return live OAuth tool backends when durable audit and resolver are available."""
    if credential_resolver is None:
        if settings.database_url:
            logger.warning(
                "DATABASE_URL is set but credential_resolver is unset — per-user OAuth tools "
                "are disabled until a credential vault is wired."
            )
        return None, None, None, None
    if settings.database_url is None:
        logger.warning(
            "OAuth tool credentials may be configured but DATABASE_URL is unset — per-user OAuth "
            "tools are disabled (idempotency requires durable audit)."
        )
        return None, None, None, None
    return GmailApiSender(), GoogleCalendarClient(), SlackUserApiSender(), credential_resolver


def default_registry(
    settings: Settings | None = None,
    credential_resolver: CredentialResolver | None = None,
) -> ToolRegistry:
    """A registry pre-loaded with the standard tools.

    Live Resend send is enabled only when ``DATABASE_URL`` (durable audit) and Resend creds are set.
    Live Slack post is enabled only when ``DATABASE_URL`` and ``SLACK_BOT_TOKEN`` are set.
    Per-user OAuth tools require ``DATABASE_URL`` and a wired ``credential_resolver``.
    """
    settings = settings or get_settings()
    sender = _resolve_email_sender(settings)
    slack_sender = _resolve_slack_sender(settings)
    gmail_sender, calendar_client, slack_user_sender, resolver = _resolve_oauth_tools(
        settings, credential_resolver
    )
    registry = ToolRegistry()
    registry.register(SearchTool())
    registry.register(SendEmailTool(sender=sender))
    registry.register(SlackPostTool(sender=slack_sender))
    _register_oauth_tools(
        registry,
        resolver,
        gmail_sender=gmail_sender,
        calendar_client=calendar_client,
        slack_user_sender=slack_user_sender,
    )
    return registry
