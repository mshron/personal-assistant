"""Email MCP tools -- FastMCP server exposing email scan, unsubscribe, and list tools."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import date
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from personal_agent.email.fastmail import FastmailProvider
from personal_agent.email.state import SubscriptionStore
from personal_agent.email.unsubscribe import Unsubscriber

mcp = FastMCP("email")


def _get_provider() -> FastmailProvider:
    api_base = os.environ.get("FASTMAIL_API_BASE", "")
    if not api_base:
        raise RuntimeError("FASTMAIL_API_BASE environment variable must be set")
    return FastmailProvider(api_base=api_base)


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

    provider = _get_provider()
    store = _get_store()

    emails = await provider.search(after_date, before_date, folder)

    if not emails:
        return f"No emails found in {folder} between {after} and {before}."

    # Group by sender
    by_sender: dict[str, list] = defaultdict(list)
    for email in emails:
        by_sender[email.sender].append(email)

    # Filter out already-processed senders (not pending)
    new_candidates: dict[str, list] = {}
    for sender, msgs in by_sender.items():
        existing = store.get_sender(sender)
        if existing is not None and existing.status != "pending":
            continue
        new_candidates[sender] = msgs

    # Record the scan
    store.add_scan(after_date, before_date, len(new_candidates))

    # Upsert new senders with status "pending"
    for sender, msgs in new_candidates.items():
        dates = [m.date for m in msgs]
        store.upsert_sender(
            sender,
            status="pending",
            email_count=len(msgs),
            first_seen=min(dates).date().isoformat(),
            last_seen=max(dates).date().isoformat(),
        )

    # Format output
    lines: list[str] = []
    lines.append(f"Email scan: {folder} from {after} to {before}")
    lines.append(f"Total emails: {len(emails)}, Unique senders: {len(by_sender)}")
    lines.append(f"New/pending candidates: {len(new_candidates)}")
    lines.append("")

    # Sort candidates by count descending
    sorted_candidates = sorted(
        new_candidates.items(), key=lambda x: len(x[1]), reverse=True
    )
    for sender, msgs in sorted_candidates:
        has_unsub = any(m.has_list_unsubscribe for m in msgs)
        unsub_label = "[has List-Unsubscribe]" if has_unsub else "[no List-Unsubscribe]"
        lines.append(f"- {sender}: {len(msgs)} emails {unsub_label}")
        sample_subjects = [m.subject for m in msgs[:3]]
        for subj in sample_subjects:
            lines.append(f"    - {subj}")

    return "\n".join(lines)


@mcp.tool()
async def email_unsubscribe(sender: str) -> str:
    """Unsubscribe from a sender's mailing list.

    Parameters
    ----------
    sender:
        The sender email address to unsubscribe from. Must exist in the
        subscription store (run email_scan first).

    Looks up the sender in the subscription store to find a message_id,
    then tries multiple unsubscribe methods (RFC 8058 one-click, mailto,
    HTTPS, body link parsing).
    """
    store = _get_store()
    provider = _get_provider()

    record = store.get_sender(sender)
    if record is None:
        return f"Sender '{sender}' not found in subscription store. Run email_scan first."

    # We need a message_id to unsubscribe. Search for a recent message from this sender.
    # Use the stored date range to find a message.
    from datetime import date as date_type

    after_date = date_type.fromisoformat(record.first_seen)
    before_date = date_type.fromisoformat(record.last_seen)
    # Extend before_date by one day to be inclusive
    from datetime import timedelta

    before_date = before_date + timedelta(days=1)

    emails = await provider.search(after_date, before_date)
    sender_emails = [e for e in emails if e.sender == sender]

    if not sender_emails:
        return f"No emails found from '{sender}' in the stored date range. Cannot unsubscribe."

    # Pick the most recent email with List-Unsubscribe if possible
    candidates = [e for e in sender_emails if e.has_list_unsubscribe]
    target = candidates[0] if candidates else sender_emails[0]

    unsubscriber = Unsubscriber(provider)
    result = await unsubscriber.unsubscribe(target.message_id)

    if result.success:
        store.upsert_sender(
            sender,
            status="unsubscribed",
            unsubscribe_method=result.method,
            unsubscribe_detail=result.detail,
        )
        return f"Successfully unsubscribed from {sender} via {result.method}: {result.detail}"
    else:
        # Keep as pending on failure
        store.upsert_sender(
            sender,
            unsubscribe_method=result.method,
            unsubscribe_detail=result.detail,
        )
        return f"Failed to unsubscribe from {sender} via {result.method}: {result.detail}"


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
