---
name: email-unsubscribe
description: Agentic email unsubscribe workflow. Use when the user wants to unsubscribe from email senders, clean up subscriptions, or manage mailing lists.
metadata: {"nanobot": {"requires": {"bins": ["agent-browser"]}}}
---

# Email Unsubscribe Workflow

Multi-step agentic workflow for unsubscribing from email mailing lists. Uses real URLs from email headers — NEVER fabricate or guess URLs.

## Overview

1. **Discover** — Use `email_accounts` to find configured accounts
2. **Search** — Use `email_search` to find senders (paginate with limit/offset)
3. **Inspect** — Use `email_get_headers` to get List-Unsubscribe URLs for specific messages
4. **Unsubscribe** — Use agent-browser to visit the real unsubscribe URL
5. **Report** — Tell the user what happened

## Step 1: Discover Accounts

```
Call email_accounts()
```

Returns a list like `["fastmail", "gmail"]`. Use these account names in subsequent calls.

## Step 2: Search for Emails

```
Call email_search(after="2026-03-01", account="fastmail", limit=20)
```

Returns paginated results with sender, subject, and `has_list_unsubscribe` flag. Page through with `offset` to see more:

```
Call email_search(after="2026-03-01", account="fastmail", limit=20, offset=20)
```

Identify senders the user wants to unsubscribe from based on the subjects and sender addresses.

## Step 3: Get Unsubscribe Headers

For messages with `has_list_unsubscribe: true`, fetch the actual unsubscribe URL:

```
Call email_get_headers(account="fastmail", message_id="msg-abc123")
```

Returns headers including `List-Unsubscribe` with real URLs. These are the ONLY URLs you should use. Example:

```json
{
  "List-Unsubscribe": "<https://real-url.example.com/unsub?token=abc123>, <mailto:unsub@example.com>",
  "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"
}
```

## Step 4: Unsubscribe Using Real URLs

**CRITICAL: Only use URLs from the List-Unsubscribe header. NEVER guess or construct URLs.**

### Method A: Visit the unsubscribe URL with agent-browser

```bash
agent-browser open "https://example.com/unsub?token=abc123"
agent-browser wait --load networkidle
agent-browser snapshot -i
```

Read the snapshot. If the page shows a confirmation button, click it. If it says "successfully unsubscribed", you're done.

### Method B: Mailto

If the List-Unsubscribe header contains a `mailto:` URL, note the address and use it to send an unsubscribe email.

### Method C: Interactive unsubscribe page

If the URL leads to a multi-step page, re-snapshot after each interaction:

```bash
agent-browser click @e3
agent-browser wait --load networkidle
agent-browser snapshot -i
```

### Method D: Cloudflare or bot detection

If the page shows a Cloudflare challenge, CAPTCHA, or blocks access, report the exact URL back to the user so they can visit it manually.

### Method E: No List-Unsubscribe header

For senders where `has_list_unsubscribe` is false, there's no URL to work with. Tell the user.

## Step 5: Clean Up

Close the browser when done:
```bash
agent-browser close
```

## Important Rules

- **NEVER fabricate URLs.** Only use URLs from `email_get_headers` output.
- Process senders ONE AT A TIME.
- ALWAYS verify by reading the page after clicking.
- NEVER enter the user's real credentials on third-party pages.
- When blocked by Cloudflare/bot detection, report the URL for manual action.
- Close the browser session when done.
