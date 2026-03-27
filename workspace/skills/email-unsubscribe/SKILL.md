---
name: email-unsubscribe
description: Agentic email unsubscribe workflow. Use when the user wants to unsubscribe from email senders, clean up subscriptions, or manage mailing lists.
metadata: {"nanobot": {"requires": {"bins": ["agent-browser"]}}}
---

# Email Unsubscribe Workflow

Multi-step agentic workflow for unsubscribing from email mailing lists. Tracks progress in the scratchpad. Uses real URLs from the email scan — NEVER fabricate or guess URLs.

## Overview

1. **Check scratchpad** — See what's already been done
2. **Scan** — Use `email_scan` to find senders (includes actual List-Unsubscribe URLs)
3. **Compare** — Cross-reference scan results with scratchpad to find new senders
4. **Unsubscribe** — Use agent-browser to visit the real unsubscribe URL
5. **Record** — Write outcome to scratchpad

## Step 1: Check What's Been Done

```
Call scratchpad_lookup(topic="email")
```

## Step 2: Scan and Compare

```
Call email_scan(after="2026-03-01")
```

The output includes `List-Unsubscribe:` headers with real URLs for each sender that has them. These are the ONLY URLs you should use. Example output:

```
- editor@members.perigold.com: 9 emails [has List-Unsubscribe]
    List-Unsubscribe: <https://real-url.example.com/unsub?token=abc123>, <mailto:unsub@example.com>
    - Sale: Up to 50% off
```

## Step 3: Unsubscribe Using Real URLs

**CRITICAL: Only use URLs from the List-Unsubscribe header in the scan output. NEVER guess or construct URLs.**

### Method A: One-Click via agent-browser (best)

If the List-Unsubscribe header contains an HTTPS URL, use agent-browser to POST to it:

```bash
# Extract the HTTPS URL from the List-Unsubscribe header
# e.g. <https://example.com/unsub?token=abc123>

# Navigate to the URL (this effectively does a GET)
agent-browser open "https://example.com/unsub?token=abc123"
agent-browser wait --load networkidle
agent-browser snapshot -i
```

Read the snapshot. If the page shows a confirmation button, click it. If it says "successfully unsubscribed", you're done.

Record the result:
```
Call scratchpad_write(topic="email", subtopic="sender@example.com", body="status=unsubscribed, method=browser_one_click, visited real unsub URL")
```

### Method B: Mailto

If the List-Unsubscribe header contains a `mailto:` URL, note the address and use it to send an unsubscribe email.

### Method C: Interactive unsubscribe page

If the one-click URL leads to a multi-step page:

```bash
agent-browser snapshot -i
# Read the page, find the confirm/unsubscribe button
agent-browser click @e3
agent-browser wait --load networkidle
agent-browser snapshot -i
# Verify confirmation
```

### Method D: No List-Unsubscribe header

For senders marked `[no List-Unsubscribe]`, you have no URL to work with. Record as skipped:
```
Call scratchpad_write(topic="email", subtopic="sender@example.com", body="status=skipped, no List-Unsubscribe header")
```

## Step 4: Clean Up

Close the browser when done:
```bash
agent-browser close
```

Report results to the user.

## Important Rules

- **NEVER fabricate URLs.** Only use URLs from the `List-Unsubscribe:` line in email_scan output.
- Process senders ONE AT A TIME.
- ALWAYS verify by reading the page after clicking.
- NEVER enter the user's real credentials on third-party pages.
- Close the browser session when done.
