"""Fastmail email provider using JMAP (RFC 8620 / RFC 8621)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from personal_agent.email.provider import EmailProvider, EmailSummary


class FastmailProvider(EmailProvider):
    """Fastmail JMAP-based email provider.

    All requests are routed through a credential proxy that injects the
    auth header.  Pass *api_base* (e.g.
    ``http://polynumeral-cred-proxy.flycast/fastmail``).
    """

    def __init__(self, api_base: str) -> None:
        if not api_base:
            raise ValueError("api_base must be provided")
        self._api_base = api_base.rstrip("/")
        self._account_id: str | None = None
        self._api_url: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json"}

    def _session_url(self) -> str:
        return f"{self._api_base}/jmap/session"

    def _rewrite_api_url(self, api_url: str) -> str:
        """Rewrite the Fastmail apiUrl to go through the proxy."""
        parsed = urlparse(api_url)
        return f"{self._api_base}{parsed.path}"

    async def _ensure_session(self) -> None:
        """Discover JMAP session if not already cached."""
        if self._account_id and self._api_url:
            return
        async with httpx.AsyncClient() as client:
            resp = await client.get(self._session_url(), headers=self._auth_headers())
            resp.raise_for_status()
            data = resp.json()
        # The primary account is the first one listed in accounts.
        self._account_id = data["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        self._api_url = self._rewrite_api_url(data["apiUrl"])

    async def _jmap_request(self, method_calls: list[list[Any]]) -> list[list[Any]]:
        """Send a JMAP request and return the method responses."""
        await self._ensure_session()
        assert self._api_url is not None
        assert self._account_id is not None

        payload = {
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
            "methodCalls": method_calls,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._api_url,
                headers=self._auth_headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        return data["methodResponses"]

    async def _resolve_mailbox_id(self, folder: str) -> str | None:
        """Resolve a folder name (e.g. 'Inbox') to a JMAP mailbox ID."""
        responses = await self._jmap_request([
            [
                "Mailbox/get",
                {"accountId": self._account_id, "properties": ["name"]},
                "mb0",
            ]
        ])
        for mailbox in responses[0][1]["list"]:
            if mailbox["name"].lower() == folder.lower():
                return mailbox["id"]
        return None

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
        await self._ensure_session()

        mailbox_id = await self._resolve_mailbox_id(folder)
        if mailbox_id is None:
            return []

        filter_condition: dict[str, Any] = {
            "inMailbox": mailbox_id,
            "after": f"{after.isoformat()}T00:00:00Z",
            "before": f"{before.isoformat()}T00:00:00Z",
        }

        responses = await self._jmap_request([
            [
                "Email/query",
                {
                    "accountId": self._account_id,
                    "filter": filter_condition,
                    "sort": [{"property": "receivedAt", "isAscending": False}],
                    "limit": 500,
                },
                "q0",
            ],
            [
                "Email/get",
                {
                    "accountId": self._account_id,
                    "#ids": {
                        "resultOf": "q0",
                        "name": "Email/query",
                        "path": "/ids",
                    },
                    "properties": [
                        "id",
                        "from",
                        "subject",
                        "receivedAt",
                        "header:List-Unsubscribe",
                    ],
                },
                "g0",
            ],
        ])

        # The second response is the Email/get result.
        emails = responses[1][1]["list"]
        results: list[EmailSummary] = []
        for email in emails:
            sender_list = email.get("from") or []
            sender = sender_list[0].get("email", "") if sender_list else ""
            received_at = email.get("receivedAt", "")
            dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            list_unsub = email.get("header:List-Unsubscribe") or ""
            results.append(
                EmailSummary(
                    message_id=email["id"],
                    sender=sender,
                    subject=email.get("subject", ""),
                    date=dt,
                    has_list_unsubscribe=bool(list_unsub),
                    list_unsubscribe=list_unsub.strip(),
                )
            )
        return results

    async def get_headers(self, message_id: str) -> dict[str, str]:
        """Return selected headers for a single message."""
        responses = await self._jmap_request([
            [
                "Email/get",
                {
                    "accountId": self._account_id,
                    "ids": [message_id],
                    "properties": [
                        "header:List-Unsubscribe",
                        "header:List-Unsubscribe-Post",
                        "header:From",
                        "header:Subject",
                    ],
                },
                "h0",
            ]
        ])
        email_list = responses[0][1].get("list", [])
        if not email_list:
            return {}
        email = email_list[0]
        headers: dict[str, str] = {}
        for key in (
            "header:List-Unsubscribe",
            "header:List-Unsubscribe-Post",
            "header:From",
            "header:Subject",
        ):
            value = email.get(key)
            if value is not None:
                # Strip the "header:" prefix for the returned dict key.
                clean_key = key.replace("header:", "")
                headers[clean_key] = value.strip()
        return headers

    async def get_body(self, message_id: str) -> str:
        """Return the body of a message (HTML preferred, falls back to text)."""
        responses = await self._jmap_request([
            [
                "Email/get",
                {
                    "accountId": self._account_id,
                    "ids": [message_id],
                    "properties": ["bodyValues", "htmlBody", "textBody"],
                    "fetchHTMLBodyValues": True,
                    "fetchTextBodyValues": True,
                },
                "b0",
            ]
        ])
        email_list = responses[0][1].get("list", [])
        if not email_list:
            return ""
        email = email_list[0]
        body_values = email.get("bodyValues", {})

        # Try HTML body first.
        for part in email.get("htmlBody", []):
            part_id = part.get("partId")
            if part_id and part_id in body_values:
                return body_values[part_id].get("value", "")

        # Fall back to text body.
        for part in email.get("textBody", []):
            part_id = part.get("partId")
            if part_id and part_id in body_values:
                return body_values[part_id].get("value", "")

        return ""

    async def send_simple(self, to: str, subject: str, body: str) -> None:
        """Send a short unsubscribe-type message via JMAP."""
        # Run base-class validation first.
        await super().send_simple(to, subject, body)

        await self._ensure_session()

        # Create a draft and send it in one request using back-references.
        responses = await self._jmap_request([
            [
                "Email/set",
                {
                    "accountId": self._account_id,
                    "create": {
                        "draft1": {
                            "to": [{"email": to}],
                            "subject": subject,
                            "bodyValues": {
                                "body": {"value": body, "charset": "utf-8"},
                            },
                            "textBody": [{"partId": "body", "type": "text/plain"}],
                            "mailboxIds": {},  # No mailbox needed for submission.
                        }
                    },
                },
                "s0",
            ],
            [
                "EmailSubmission/set",
                {
                    "accountId": self._account_id,
                    "create": {
                        "sub1": {
                            "emailId": "#draft1",
                            "envelope": {
                                "mailFrom": {"email": ""},  # Server fills from identity.
                                "rcptTo": [{"email": to}],
                            },
                        }
                    },
                    "onSuccessDestroyEmail": ["#sub1"],
                },
                "s1",
            ],
        ])

        # Check for errors in Email/set.
        email_set_resp = responses[0][1]
        if email_set_resp.get("notCreated"):
            errors = email_set_resp["notCreated"]
            raise RuntimeError(f"Failed to create draft email: {errors}")

        # Check for errors in EmailSubmission/set.
        sub_resp = responses[1][1]
        if sub_resp.get("notCreated"):
            errors = sub_resp["notCreated"]
            raise RuntimeError(f"Failed to submit email: {errors}")
