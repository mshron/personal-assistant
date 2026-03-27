---
name: email-unsubscribe
description: Agentic email unsubscribe workflow. Use when the user wants to unsubscribe from email senders, clean up subscriptions, or manage mailing lists.
metadata: {"nanobot": {"requires": {"bins": ["agent-browser"]}}}
---

# Email Unsubscribe Workflow

Multi-step agentic workflow for unsubscribing from email mailing lists. Uses real URLs from the email scan — NEVER fabricate or guess URLs.

## Overview

1. **Scan** — Use `email_scan` to find senders (includes actual List-Unsubscribe URLs)
2. **Unsubscribe** — Use agent-browser to visit the real unsubscribe URL
3. **Report** — Tell the user what happened

## Step 1: Scan

```
Call email_scan(after="2026-03-01")
```

The output includes `List-Unsubscribe:` headers with real URLs. These are the ONLY URLs you should use. Example:

```
- editor@members.perigold.com: 9 emails [has List-Unsubscribe]
    List-Unsubscribe: <https://real-url.example.com/unsub?token=abc123>, <mailto:unsub@example.com>
    - Sale: Up to 50% off
```

## Step 2: Unsubscribe Using Real URLs

**CRITICAL: Only use URLs from the List-Unsubscribe header in the scan output. NEVER guess or construct URLs.**

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

For senders marked `[no List-Unsubscribe]`, there's no URL to work with. Tell the user.

## Step 3: Clean Up

Close the browser when done:
```bash
agent-browser close
```

## Important Rules

- **NEVER fabricate URLs.** Only use URLs from the `List-Unsubscribe:` line in email_scan output.
- Process senders ONE AT A TIME.
- ALWAYS verify by reading the page after clicking.
- NEVER enter the user's real credentials on third-party pages.
- When blocked by Cloudflare/bot detection, report the URL for manual action.
- Close the browser session when done.
