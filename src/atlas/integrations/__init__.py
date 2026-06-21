"""External service integrations (email, future Slack/Jira/Calendar adapters)."""

from atlas.integrations.email import (
    EmailMessage,
    EmailSender,
    FakeEmailSender,
    ResendEmailSender,
    build_email_sender,
)

__all__ = [
    "EmailMessage",
    "EmailSender",
    "FakeEmailSender",
    "ResendEmailSender",
    "build_email_sender",
]
