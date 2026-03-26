---
name: email-unsubscribe
description: Agentic email unsubscribe workflow. Use when the user wants to unsubscribe from email senders, clean up subscriptions, or manage mailing lists.
metadata: {"nanobot": {"requires": {"bins": ["agent-browser"]}}}
---

# Email Unsubscribe Workflow

Multi-step agentic workflow for unsubscribing from email mailing lists. Uses deterministic methods first (fast, cheap) and falls back to browser automation (reliable, handles JavaScript pages). Tracks progress in the scratchpad.

## Overview

1. **Check scratchpad** — Use `scratchpad_lookup(topic="email")` to see what's already been done
2. **Scan** — Use `email_scan` to find senders and their unsubscribe capabilities
3. **Compare** — Cross-reference scan results with scratchpad to find new senders
4. **Unsubscribe** — Try methods in order: RFC 8058 one-click > mailto > browser
5. **Record** — Write outcome to scratchpad with `scratchpad_write`

## Step 1: Check What's Been Done

```
Call scratchpad_lookup(topic="email")
```

This shows all prior activity — which senders have been unsubscribed, attempted, or skipped.

## Step 2: Scan and Compare

```
Call email_scan(after="2026-03-01", before="2026-03-25")
```

Returns all senders with email counts and `[has List-Unsubscribe]` labels. Compare with the scratchpad to identify senders not yet processed.

## Step 3: For Each New Sender, Try Methods in Order

### Method A: RFC 8058 One-Click (best)

If the sender has `[has List-Unsubscribe]`, try one-click first via `exec`:

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST \
  -d "List-Unsubscribe=One-Click" \
  "UNSUBSCRIBE_URL_FROM_HEADER"
```

If 200-299, record it:
```
Call scratchpad_write(topic="email", subtopic="news@example.com", body="status=unsubscribed, method=one_click, POST -> 200")
```

### Method B: Mailto (good)

If the List-Unsubscribe header contains a `mailto:` URL, send an unsubscribe email. Record the outcome to scratchpad.

### Method C: Browser Automation (fallback)

When deterministic methods fail or aren't available, use `agent-browser`:

```bash
agent-browser open "https://example.com/unsubscribe?token=abc123"
agent-browser wait --load networkidle
agent-browser snapshot -i
```

**Read the snapshot.** Look for:
- A "Confirm" or "Unsubscribe" button -> click it
- A form asking for email address -> fill it and submit
- A "You have been unsubscribed" message -> already done
- A CAPTCHA or login wall -> mark as "attempted" and move on

```bash
agent-browser click @e3
agent-browser wait --load networkidle
agent-browser snapshot -i
```

**Read the result.** If confirmed:
```
Call scratchpad_write(topic="email", subtopic="news@example.com", body="status=unsubscribed, method=browser, clicked confirm, saw 'You have been unsubscribed'")
```

If unclear:
```
Call scratchpad_write(topic="email", subtopic="news@example.com", body="status=attempted, method=browser, clicked confirm but no confirmation message")
```

## Step 4: Handle Edge Cases

**Multi-step pages:** Re-snapshot after each interaction and respond to what's on the page.

**JavaScript-heavy pages:** Always use `agent-browser wait --load networkidle`. If empty, try `agent-browser wait 3000` then re-snapshot.

**"Manage preferences":** Look for "Unsubscribe from all" or uncheck all categories.

## Step 5: Clean Up

Close the browser when done:
```bash
agent-browser close
```

Report results to the user: how many unsubscribed, attempted, skipped.

## Important Rules

- Process senders ONE AT A TIME.
- ALWAYS verify by reading the page after clicking.
- NEVER enter the user's real credentials on third-party pages. Skip and mark "attempted".
- Close the browser session when done.
