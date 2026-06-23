"""External service integrations (email, Slack, future Jira/Calendar adapters)."""

from atlas.integrations.email import (
    EmailMessage,
    EmailSender,
    FakeEmailSender,
    ResendEmailSender,
    build_email_sender,
)
from atlas.integrations.slack import (
    FakeSlackSender,
    SlackApiSender,
    SlackMessage,
    SlackSender,
    build_slack_sender,
)

__all__ = [
    "EmailMessage",
    "EmailSender",
    "FakeEmailSender",
    "ResendEmailSender",
    "build_email_sender",
    "FakeSlackSender",
    "SlackApiSender",
    "SlackMessage",
    "SlackSender",
    "build_slack_sender",
]
