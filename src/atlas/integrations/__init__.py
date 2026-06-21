"""External service integrations (email, future Slack/Jira/Calendar adapters)."""

from atlas.integrations.email import (
    EmailMessage,
    EmailSender,
    ResendEmailSender,
    build_email_sender,
)

__all__ = ["EmailMessage", "EmailSender", "ResendEmailSender", "build_email_sender"]
