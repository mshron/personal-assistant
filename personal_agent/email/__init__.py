"""Email provider abstraction layer."""

from personal_agent.email.fastmail import FastmailProvider
from personal_agent.email.gmail import GmailProvider
from personal_agent.email.provider import EmailProvider, EmailSummary

__all__ = ["EmailProvider", "EmailSummary", "FastmailProvider", "GmailProvider"]
