---
name: scratchpad
description: General-purpose working notes organized by topic. Use to track activity state across sessions (email unsubscribes, research, tasks).
always: true
---

# Scratchpad

Persistent working notes organized by topic. Not a database — a notepad. Entries may go stale or get superseded. Use it to track activities in progress across sessions.

## MCP Tools

- **`scratchpad_write(topic, body, subtopic=None)`** — Write a note. Creates the topic if new.
- **`scratchpad_lookup(topic, subtopic=None)`** — Read entries. If subtopic given, filters to that key. If blank, returns everything in the topic.
- **`scratchpad_list(topic=None)`** — If topic given, lists subtopics. If blank, lists all topics.

## Direct File Access

Scratchpad files live at `scratchpad/{topic}.jsonl` in the workspace. Each line is JSON:

```json
{"subtopic": "sender@spam.com", "body": "status=unsubscribed, method=one_click", "created_at": "2026-03-26T14:30:00Z"}
```

You can search directly with `exec`:

```bash
grep -i "keyword" scratchpad/email.jsonl        # Search within a topic
grep -rl "keyword" scratchpad/                   # Search across all topics
```

Or use `read_file` on `scratchpad/{topic}.jsonl` to see everything.

## Conventions

- Writes are append-only. To "update" a subtopic, write a new entry — the latest entry is the current state.
- Use subtopics as keys when you'll want to look them up later (e.g., email addresses, task IDs).
- Omit subtopic for general notes on a topic (e.g., "Scanned inbox Mar 1-25, found 47 candidates").
