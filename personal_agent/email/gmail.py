"""Gmail email provider using the Gmail REST API."""

from __future__ import annotations

import base64
from datetime import date, datetime, timezone
from email.mime.text import MIMEText
from typing import Any

import httpx

from personal_agent.email.provider import EmailProvider, EmailSummary

# Gmail uses label IDs instead of folder names.
_FOLDER_TO_LABEL: dict[str, str] = {
    "inbox": "INBOX",
    "sent": "SENT",
    "drafts": "DRAFT",
    "trash": "TRASH",
    "spam": "SPAM",
    "starred": "STARRED",
    "important": "IMPORTANT",
    "unread": "UNREAD",
}


class GmailProvider(EmailProvider):
    """Gmail REST API email provider.

    All requests are routed through a credential proxy that injects the
    OAuth2 Bearer token.  Pass *api_base* (e.g.
    ``http://polynumeral-cred-proxy.flycast/gmail``).
    """

    def __init__(self, api_base: str) -> None:
        if not api_base:
            raise ValueError("api_base must be provided")
        self._api_base = api_base.rstrip("/")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        """Build a full URL for a Gmail API path."""
        return f"{self._api_base}/gmail/v1/users/me{path}"

    def _headers(self) -> dict[str, str]:
        """Common request headers. No auth -- proxy handles it."""
        return {"Content-Type": "application/json"}

    @staticmethod
    def _resolve_label_id(folder: str) -> str:
        """Map a human-friendly folder name to a Gmail label ID."""
        return _FOLDER_TO_LABEL.get(folder.lower(), folder)

    @staticmethod
    def _find_header(headers: list[dict[str, str]], name: str) -> str | None:
        """Find a header value by name in a Gmail payload headers list."""
        for h in headers:
            if h["name"].lower() == name.lower():
                return h["value"]
        return None

    @staticmethod
    def _extract_body(payload: dict[str, Any]) -> str:
        """Extract body text from a Gmail message payload.

        Prefers text/html, falls back to text/plain.
        Handles both simple and multipart message structures.
        """
        # Simple single-part message
        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data")

        if mime_type == "text/html" and body_data:
            return base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")

        if mime_type == "text/plain" and body_data:
            plain_text = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
            # Keep looking for HTML in parts, but remember plain text
        else:
            plain_text = ""

        # Multipart -- recurse into parts
        parts = payload.get("parts", [])
        html_body = ""
        for part in parts:
            part_mime = part.get("mimeType", "")
            part_data = part.get("body", {}).get("data")

            if part_mime == "text/html" and part_data:
                html_body = base64.urlsafe_b64decode(part_data).decode("utf-8", errors="replace")
            elif part_mime == "text/plain" and part_data and not plain_text:
                plain_text = base64.urlsafe_b64decode(part_data).decode("utf-8", errors="replace")
            elif part.get("parts"):
                # Nested multipart (e.g. multipart/alternative inside multipart/mixed)
                nested = GmailProvider._extract_body(part)
                if nested:
                    if part_mime.startswith("text/html") or "<" in nested[:100]:
                        html_body = html_body or nested
                    else:
                        plain_text = plain_text or nested

        return html_body or plain_text

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def search(
        self,
        after: date,
        before: date,
        folder: str = "Inbox",
    ) -> list[EmailSummary]:
        """Search for emails in *folder* within the given date range."""
        label_id = self._resolve_label_id(folder)

        # Gmail search query uses YYYY/MM/DD format
        q = f"after:{after.strftime('%Y/%m/%d')} before:{before.strftime('%Y/%m/%d')}"

        params: dict[str, Any] = {
            "q": q,
            "labelIds": label_id,
            "maxResults": 500,
        }

        async with httpx.AsyncClient() as client:
            # Step 1: List message IDs
            resp = await client.get(
                self._url("/messages"),
                headers=self._headers(),
                params=params,
            )
            resp.raise_for_status()
            data = resp.json()

        message_stubs = data.get("messages", [])
        if not message_stubs:
            return []

        # Step 2: Fetch message metadata concurrently (up to 20 at a time)
        import asyncio

        sem = asyncio.Semaphore(20)

        async def _fetch_one(client: httpx.AsyncClient, msg_id: str) -> EmailSummary:
            async with sem:
                resp = await client.get(
                    self._url(f"/messages/{msg_id}"),
                    headers=self._headers(),
                    params={"format": "metadata", "metadataHeaders": [
                        "From", "Subject", "Date", "List-Unsubscribe",
                    ]},
                )
                resp.raise_for_status()
                msg = resp.json()

            headers = msg.get("payload", {}).get("headers", [])
            from_header = self._find_header(headers, "From") or ""
            subject = self._find_header(headers, "Subject") or ""
            list_unsub = self._find_header(headers, "List-Unsubscribe")

            sender = from_header
            if "<" in from_header and ">" in from_header:
                sender = from_header.split("<")[1].split(">")[0]

            internal_date_ms = int(msg.get("internalDate", "0"))
            dt = datetime.fromtimestamp(
                internal_date_ms / 1000, tz=timezone.utc
            )

            return EmailSummary(
                message_id=msg_id,
                sender=sender,
                subject=subject,
                date=dt,
                has_list_unsubscribe=bool(list_unsub),
            )

        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(
                *[_fetch_one(client, stub["id"]) for stub in message_stubs]
            )

        return list(results)

    async def get_headers(self, message_id: str) -> dict[str, str]:
        """Return selected headers for a single message."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._url(f"/messages/{message_id}"),
                headers=self._headers(),
                params={"format": "metadata", "metadataHeaders": [
                    "List-Unsubscribe", "List-Unsubscribe-Post", "From", "Subject",
                ]},
            )
            resp.raise_for_status()
            msg = resp.json()

        payload_headers = msg.get("payload", {}).get("headers", [])
        result: dict[str, str] = {}
        for name in ("List-Unsubscribe", "List-Unsubscribe-Post", "From", "Subject"):
            value = self._find_header(payload_headers, name)
            if value is not None:
                result[name] = value.strip()
        return result

    async def get_body(self, message_id: str) -> str:
        """Return the body of a message (HTML preferred, falls back to text)."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._url(f"/messages/{message_id}"),
                headers=self._headers(),
                params={"format": "full"},
            )
            resp.raise_for_status()
            msg = resp.json()

        payload = msg.get("payload", {})
        return self._extract_body(payload)

    async def send_simple(self, to: str, subject: str, body: str) -> None:
        """Send a short unsubscribe-type message via Gmail API."""
        # Run base-class validation first.
        await super().send_simple(to, subject, body)

        # Build RFC 2822 MIME message and base64url encode it
        mime_msg = MIMEText(body, "plain", "utf-8")
        mime_msg["To"] = to
        mime_msg["Subject"] = subject
        raw = base64.urlsafe_b64encode(
            mime_msg.as_bytes()
        ).decode("ascii")

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._url("/messages/send"),
                headers=self._headers(),
                json={"raw": raw},
            )
            resp.raise_for_status()
