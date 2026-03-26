"""Email MCP tools -- FastMCP server exposing email scan, unsubscribe, and list tools."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import date
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from personal_agent.email.fastmail import FastmailProvider
from personal_agent.email.gmail import GmailProvider
from personal_agent.email.provider import EmailProvider
from personal_agent.email.state import SubscriptionStore

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


def _get_store() -> SubscriptionStore:
    path_str = os.environ.get("EMAIL_SUBSCRIPTIONS_FILE", "/data/email_subscriptions.json")
    store = SubscriptionStore(Path(path_str))
    store.load()
    return store


@mcp.tool()
async def email_scan(after: str, before: str, folder: str = "Inbox") -> str:
    """Scan emails in a date range and group by sender.

    Parameters
    ----------
    after:
        Start date (ISO format, e.g. "2026-03-01").
    before:
        End date (ISO format, e.g. "2026-03-07").
    folder:
        Mailbox folder to scan (default "Inbox").

    Returns a formatted report of senders with email counts,
    unsubscribe availability, and sample subjects. Senders already
    processed in the subscription store are skipped.
    """
    after_date = date.fromisoformat(after)
    before_date = date.fromisoformat(before)

    providers = _get_providers()
    store = _get_store()

    # Collect emails from all providers, tagging each with its provider name
    all_emails = []
    provider_for_sender: dict[str, str] = {}

    for provider_name, provider in providers:
        emails = await provider.search(after_date, before_date, folder)
        for email in emails:
            all_emails.append(email)
            # Track which provider a sender came from (first seen wins)
            if email.sender not in provider_for_sender:
                provider_for_sender[email.sender] = provider_name

    if not all_emails:
        return f"No emails found in {folder} between {after} and {before}."

    # Group by sender
    by_sender: dict[str, list] = defaultdict(list)
    for email in all_emails:
        by_sender[email.sender].append(email)

    # Filter out already-processed senders (not pending)
    new_candidates: dict[str, list] = {}
    for sender, msgs in by_sender.items():
        existing = store.get_sender(sender)
        if existing is not None and existing.status not in ("pending", "attempted"):
            continue
        new_candidates[sender] = msgs

    # Record the scan
    store.add_scan(after_date, before_date, len(new_candidates))

    # Upsert new senders with status "pending" and provider tracking
    for sender, msgs in new_candidates.items():
        dates = [m.date for m in msgs]
        store.upsert_sender(
            sender,
            status="pending",
            email_count=len(msgs),
            first_seen=min(dates).date().isoformat(),
            last_seen=max(dates).date().isoformat(),
            provider=provider_for_sender.get(sender, ""),
        )

    # Format output
    lines: list[str] = []
    lines.append(f"Email scan: {folder} from {after} to {before}")
    lines.append(f"Total emails: {len(all_emails)}, Unique senders: {len(by_sender)}")
    lines.append(f"New/pending candidates: {len(new_candidates)}")
    lines.append("")

    # Sort candidates by count descending
    sorted_candidates = sorted(
        new_candidates.items(), key=lambda x: len(x[1]), reverse=True
    )
    for sender, msgs in sorted_candidates:
        has_unsub = any(m.has_list_unsubscribe for m in msgs)
        unsub_label = "[has List-Unsubscribe]" if has_unsub else "[no List-Unsubscribe]"
        provider_label = f" ({provider_for_sender.get(sender, '')})" if len(providers) > 1 else ""
        lines.append(f"- {sender}: {len(msgs)} emails {unsub_label}{provider_label}")
        sample_subjects = [m.subject for m in msgs[:3]]
        for subj in sample_subjects:
            lines.append(f"    - {subj}")

    return "\n".join(lines)


@mcp.tool()
async def email_update_status(
    sender: str,
    status: str,
    method: str = "",
    detail: str = "",
) -> str:
    """Update a sender's subscription status in the store.

    Parameters
    ----------
    sender:
        The sender email address. Must exist in the subscription store.
    status:
        New status: "unsubscribed", "attempted", "skipped", or "pending".
    method:
        How the unsubscribe was performed (e.g. "one_click", "mailto",
        "browser"). Optional.
    detail:
        Human-readable detail about the outcome. Optional.
    """
    store = _get_store()
    record = store.get_sender(sender)
    if record is None:
        return f"Sender '{sender}' not found in subscription store. Run email_scan first."

    kwargs: dict = {"status": status}
    if method:
        kwargs["unsubscribe_method"] = method
    if detail:
        kwargs["unsubscribe_detail"] = detail

    store.upsert_sender(sender, **kwargs)
    return f"Updated {sender}: status={status}" + (f", method={method}" if method else "")


@mcp.tool()
async def email_list_subscriptions(status: str | None = None) -> str:
    """List known email subscriptions from the store.

    Parameters
    ----------
    status:
        Optional filter: "active", "unsubscribed", "pending", or "skipped".
        If omitted, returns all senders.
    """
    store = _get_store()
    senders = store.list_senders(status)

    if not senders:
        filter_msg = f" with status '{status}'" if status else ""
        return f"No subscriptions found{filter_msg}."

    lines: list[str] = []
    filter_msg = f" (status: {status})" if status else ""
    lines.append(f"Known subscriptions{filter_msg}: {len(senders)}")
    lines.append("")

    for s in sorted(senders, key=lambda x: x.email_count, reverse=True):
        method_info = ""
        if s.unsubscribe_method:
            method_info = f" [{s.unsubscribe_method}]"
        lines.append(
            f"- {s.sender}: {s.email_count} emails, status={s.status}{method_info}"
        )

    return "\n".join(lines)


def main() -> None:
    """Run the email MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
