"""Email MCP tools -- FastMCP server exposing composable email tools."""

from __future__ import annotations

import json
import os
from datetime import date

from mcp.server.fastmcp import FastMCP

from personal_agent.email.fastmail import FastmailProvider
from personal_agent.email.gmail import GmailProvider
from personal_agent.email.provider import EmailProvider

mcp = FastMCP("email")


def _get_providers() -> list[tuple[str, EmailProvider]]:
    """Return a list of (name, provider) tuples for all configured email providers.

    At least one provider must be configured or a RuntimeError is raised.
    """
    providers: list[tuple[str, EmailProvider]] = []

    fastmail_base = os.environ.get("FASTMAIL_API_BASE", "")
    if fastmail_base:
        providers.append(("fastmail", FastmailProvider(api_base=fastmail_base)))

    gmail_base = os.environ.get("GMAIL_API_BASE", "")
    if gmail_base:
        providers.append(("gmail", GmailProvider(api_base=gmail_base)))

    if not providers:
        raise RuntimeError(
            "No email providers configured. Set FASTMAIL_API_BASE and/or GMAIL_API_BASE."
        )
    return providers


def _get_provider(account: str) -> EmailProvider | None:
    """Look up a single provider by account name. Returns None if not found."""
    for name, provider in _get_providers():
        if name == account:
            return provider
    return None


@mcp.tool()
async def email_accounts() -> str:
    """List configured email account names.

    Returns a JSON array of account names, e.g. ["fastmail", "gmail"].
    Use these names with email_search, email_get_headers, and email_get_body.
    """
    providers = _get_providers()
    return json.dumps([name for name, _ in providers])


@mcp.tool()
async def email_search(
    after: str,
    before: str = "",
    folder: str = "Inbox",
    account: str = "",
    limit: int = 20,
    offset: int = 0,
) -> str:
    """Search emails in a date range with pagination.

    Parameters
    ----------
    after:
        Start date (ISO format, e.g. "2026-03-01").
    before:
        End date (ISO format, e.g. "2026-03-26"). Defaults to today.
    folder:
        Mailbox folder to scan (default "Inbox").
    account:
        Account name from email_accounts(). If empty, searches all accounts.
    limit:
        Max emails to return (default 20, max 50).
    offset:
        Number of results to skip (default 0).

    Returns JSON with total count and email summaries.
    """
    limit = min(limit, 50)
    after_date = date.fromisoformat(after)
    before_date = date.fromisoformat(before) if before else date.today()

    if account:
        provider = _get_provider(account)
        if provider is None:
            names = [n for n, _ in _get_providers()]
            return f"Error: unknown account '{account}'. Available accounts: {names}"
        result = await provider.search(after_date, before_date, folder, limit=limit, offset=offset)
        emails_out = [
            {
                "account": account,
                "message_id": e.message_id,
                "sender": e.sender,
                "subject": e.subject,
                "date": e.date.isoformat(),
                "has_list_unsubscribe": e.has_list_unsubscribe,
            }
            for e in result.emails
        ]
        return json.dumps({"total": result.total, "offset": offset, "limit": limit, "emails": emails_out})

    # Search all accounts, merge by date descending
    all_tagged: list[tuple[str, object]] = []
    total = 0
    for name, provider in _get_providers():
        # Fetch enough to cover the requested window after merge
        result = await provider.search(after_date, before_date, folder, limit=offset + limit, offset=0)
        total += result.total
        for e in result.emails:
            all_tagged.append((name, e))

    # Sort merged results by date descending
    all_tagged.sort(key=lambda x: x[1].date, reverse=True)

    # Apply offset/limit to the merged set
    page = all_tagged[offset : offset + limit]

    emails_out = [
        {
            "account": acct,
            "message_id": e.message_id,
            "sender": e.sender,
            "subject": e.subject,
            "date": e.date.isoformat(),
            "has_list_unsubscribe": e.has_list_unsubscribe,
        }
        for acct, e in page
    ]
    return json.dumps({"total": total, "offset": offset, "limit": limit, "emails": emails_out})


@mcp.tool()
async def email_get_headers(account: str, message_id: str) -> str:
    """Get headers for a specific email message.

    Parameters
    ----------
    account:
        Account name from email_accounts().
    message_id:
        Message ID from email_search results.

    Returns JSON dict of headers (From, Subject, List-Unsubscribe, etc.).
    """
    provider = _get_provider(account)
    if provider is None:
        names = [n for n, _ in _get_providers()]
        return f"Error: unknown account '{account}'. Available accounts: {names}"
    headers = await provider.get_headers(message_id)
    return json.dumps(headers)


@mcp.tool()
async def email_get_body(account: str, message_id: str) -> str:
    """Get the body of a specific email message.

    Parameters
    ----------
    account:
        Account name from email_accounts().
    message_id:
        Message ID from email_search results.

    Returns the message body (HTML preferred, falls back to plain text).
    """
    provider = _get_provider(account)
    if provider is None:
        names = [n for n, _ in _get_providers()]
        return f"Error: unknown account '{account}'. Available accounts: {names}"
    return await provider.get_body(message_id)


def main() -> None:
    """Run the email MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
