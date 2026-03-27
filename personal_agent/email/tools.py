"""Email MCP tools -- FastMCP server exposing email scan."""

from __future__ import annotations

import os
from collections import defaultdict
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


@mcp.tool()
async def email_scan(after: str, before: str = "", folder: str = "Inbox") -> str:
    """Scan emails in a date range and group by sender.

    Parameters
    ----------
    after:
        Start date (ISO format, e.g. "2026-03-01").
    before:
        End date (ISO format, e.g. "2026-03-26"). Defaults to today.
    folder:
        Mailbox folder to scan (default "Inbox").

    Returns a formatted report of all senders with email counts,
    unsubscribe availability, and sample subjects.
    """
    after_date = date.fromisoformat(after)
    before_date = date.fromisoformat(before) if before else date.today()

    providers = _get_providers()

    # Collect emails from all providers, tagging each with its provider name
    all_emails = []
    provider_for_sender: dict[str, str] = {}

    for provider_name, provider in providers:
        emails = await provider.search(after_date, before_date, folder)
        for email in emails:
            all_emails.append(email)
            if email.sender not in provider_for_sender:
                provider_for_sender[email.sender] = provider_name

    if not all_emails:
        return f"No emails found in {folder} between {after} and {before}."

    # Group by sender
    by_sender: dict[str, list] = defaultdict(list)
    for email in all_emails:
        by_sender[email.sender].append(email)

    # Format output — all senders, sorted by count descending
    lines: list[str] = []
    lines.append(f"Email scan: {folder} from {after} to {before}")
    lines.append(f"Total emails: {len(all_emails)}, Unique senders: {len(by_sender)}")
    lines.append("")

    sorted_senders = sorted(by_sender.items(), key=lambda x: len(x[1]), reverse=True)
    for sender, msgs in sorted_senders:
        has_unsub = any(m.has_list_unsubscribe for m in msgs)
        unsub_label = "[has List-Unsubscribe]" if has_unsub else "[no List-Unsubscribe]"
        provider_label = f" ({provider_for_sender.get(sender, '')})" if len(providers) > 1 else ""
        lines.append(f"- {sender}: {len(msgs)} emails {unsub_label}{provider_label}")
        # Include the actual List-Unsubscribe header from the first email that has one
        if has_unsub:
            unsub_msg = next((m for m in msgs if m.list_unsubscribe), None)
            if unsub_msg:
                lines.append(f"    List-Unsubscribe: {unsub_msg.list_unsubscribe}")
        sample_subjects = [m.subject for m in msgs[:3]]
        for subj in sample_subjects:
            lines.append(f"    - {subj}")

    return "\n".join(lines)


def main() -> None:
    """Run the email MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
