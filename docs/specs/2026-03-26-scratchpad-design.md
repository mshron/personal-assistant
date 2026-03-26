# Topic-Based Scratchpad

## Problem

The agent needs persistent working state across sessions (e.g., which email senders have been unsubscribed, research notes, task progress). The current approach is a domain-specific JSON store (`email/state.py`) with domain-specific MCP tools. This is rigid — each new domain needs its own store and tools — and positions the data as authoritative state rather than working notes, which creates problems when reality diverges (e.g., user re-subscribes to something).

## Design

A general-purpose scratchpad organized by topic. Not a database — a notepad. Entries may go stale or get superseded. The agent uses it to track activities across sessions and can search/read it directly via filesystem tools.

## Data Model

Each topic is a JSONL file at `workspace/scratchpad/{topic}.jsonl`. Each line:

```json
{"subtopic": "sender@spam.com", "body": "status=unsubscribed, method=one_click", "created_at": "2026-03-26T14:30:00Z"}
{"subtopic": null, "body": "Scanned inbox Mar 1-25, found 47 candidates", "created_at": "2026-03-26T14:28:00Z"}
```

Fields:
- `subtopic` — optional key for filtering. When present, lookup can filter to entries with that key.
- `body` — freeform text, whatever the agent wants to record.
- `created_at` — UTC ISO timestamp, set automatically on write.

No schema enforcement on body. Writes are append-only. "Updating" means appending a new entry — the full history is preserved.

## MCP Tools (3)

### `scratchpad_write(topic, body, subtopic=None)`

Appends a JSONL line to `scratchpad/{topic}.jsonl`. Creates the file if it doesn't exist. Returns confirmation with timestamp.

### `scratchpad_lookup(topic, subtopic=None)`

If subtopic is given: returns all entries with that subtopic key, chronologically.
If subtopic is blank: returns all entries in the file, chronologically.

Both cases return the full matching history, not just the latest entry.

### `scratchpad_list(topic=None)`

If topic is given: lists distinct subtopics in that topic file (with count and latest timestamp for each).
If topic is blank: lists all topic files (with entry count and latest timestamp for each).

## Agent Access Beyond MCP

The scratchpad skill documents that files live at `scratchpad/{topic}.jsonl` within the workspace. The agent can use existing tools directly:

- `grep -i "spam.com" scratchpad/email.jsonl` — search within a topic
- `grep -rl "keyword" scratchpad/` — search across all topics
- `read_file scratchpad/email.jsonl` — read everything in a topic
- `ls scratchpad/` — see all topics

## File Location

Base path: `workspace/scratchpad/` (inside nanobot workspace, already writable, persists on Fly volume). Configured via `SCRATCHPAD_DIR` env var defaulting to `scratchpad/` relative to workspace root.

## Migration: Email Subscription State

The existing email-specific state system (`email/state.py`, `SubscriptionStore`, `email_update_status`, `email_list_subscriptions`) is replaced:

| Before | After |
|---|---|
| `email_update_status(sender, status, method, detail)` | `scratchpad_write(topic="email", subtopic="sender@spam.com", body="status=unsubscribed, method=one_click")` |
| `email_list_subscriptions(status="pending")` | `scratchpad_lookup(topic="email")` or `grep "pending" scratchpad/email.jsonl` |
| `email_scan` writes to SubscriptionStore | `email_scan` writes to scratchpad |

`email_scan` stays as an MCP tool (it talks to Fastmail/Gmail APIs) but records results via scratchpad instead of the subscription store.

## Skill Updates

### New: scratchpad skill
Teaches the agent the three MCP tools and the file layout for direct filesystem access.

### Updated: email-unsubscribe skill
References scratchpad instead of `email_update_status`. Instructs the agent to write unsubscribe outcomes to `scratchpad_write(topic="email", ...)`.

## Testing

- Unit tests for the scratchpad MCP tools (write, lookup, list)
- Test that `email_scan` writes to scratchpad
- Verify grep/read_file work on scratchpad JSONL files
- Docker build with all changes
- Fly.io deploy
