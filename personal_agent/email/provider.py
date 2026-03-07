"""Abstract email provider and shared data types."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import date, datetime


@dataclass
class EmailSummary:
    """Lightweight summary of an email message."""

    message_id: str
    sender: str
    subject: str
    date: datetime
    has_list_unsubscribe: bool


# Pattern that loosely matches unsubscribe-style content.
_UNSUBSCRIBE_RE = re.compile(r"unsub", re.IGNORECASE)

_SEND_SIMPLE_MAX_BODY_LEN = 50


class EmailProvider(ABC):
    """Abstract base class for email providers.

    Deliberately omits any delete method -- this is a safety constraint
    so that automated tooling cannot permanently destroy mail.
    """

    @abstractmethod
    async def search(
        self,
        after: date,
        before: date,
        folder: str = "Inbox",
    ) -> list[EmailSummary]:
        """Return summaries of messages in *folder* within the date range."""
        ...

    @abstractmethod
    async def get_headers(self, message_id: str) -> dict[str, str]:
        """Return all headers for a single message."""
        ...

    @abstractmethod
    async def get_body(self, message_id: str) -> str:
        """Return the plain-text (or stripped HTML) body of a message."""
        ...

    async def send_simple(self, to: str, subject: str, body: str) -> None:
        """Send a short, constrained message -- intended only for unsubscribe requests.

        Raises ``ValueError`` if the body is too long or does not look like
        an unsubscribe message.  Subclasses should call ``super().send_simple(...)``
        first to run validation, then perform the actual send.
        """
        if len(body) > _SEND_SIMPLE_MAX_BODY_LEN:
            raise ValueError(
                f"Body exceeds {_SEND_SIMPLE_MAX_BODY_LEN} characters "
                f"({len(body)} given). send_simple is only for short "
                "unsubscribe-type messages."
            )
        if not _UNSUBSCRIBE_RE.search(body) and not _UNSUBSCRIBE_RE.search(subject):
            raise ValueError(
                "Message does not appear to be unsubscribe-related. "
                "send_simple is restricted to unsubscribe-type content."
            )
