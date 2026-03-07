# Email Unsubscribe Agent

## Goal

Automate email unsubscription: scan emails, identify subscription/marketing senders, present candidates for review in Zulip, and unsubscribe from approved ones.

## Architecture

```
personal_agent/
  email/
    provider.py          # Abstract EmailProvider interface
    fastmail.py          # JMAP implementation
    unsubscribe.py       # Unsubscribe logic (headers, links, browser)
    tools.py             # Nanobot MCP tools exposed to the agent
```

## Email Provider Interface

```python
class EmailProvider(ABC):
    async def search(self, after: date, before: date, folder: str = "Inbox") -> list[EmailSummary]
    async def get_headers(self, message_id: str) -> dict[str, str]
    async def get_body(self, message_id: str) -> str
    async def send_simple(self, to: str, subject: str, body: str)  # max ~50 chars body
```

`EmailSummary` contains: message_id, sender, subject, date, has_list_unsubscribe (bool).

`FastmailProvider` implements this via JMAP. Gmail gets added later with the same interface.

## Tools (MCP)

| Tool | Purpose |
|------|---------|
| `email_scan` | Scan emails in a date range, return subscription candidates grouped by sender. Params: `after`, `before`, optional `folder` |
| `email_unsubscribe` | Unsubscribe from a specific sender. Tries methods in order (see below). Params: `sender_email` or `message_id` |
| `email_list_subscriptions` | Show known subscriptions and their status (active, unsubscribed, pending) |

## Unsubscribe Methods (tried in order)

1. `List-Unsubscribe-Post` header -> HTTP POST with `List-Unsubscribe=One-Click` (RFC 8058)
2. `List-Unsubscribe` mailto: -> send short email ("unsubscribe") via provider.send_simple
3. `List-Unsubscribe` https: -> GET/POST the URL
4. Body link parsing -> find unsubscribe URLs in email body, visit via Playwright

## Zulip Review Flow

1. Agent scans a date range, groups by sender, posts to a Zulip topic (e.g. "Email > Unsubscribe Review"):
   ```
   Unsubscribe candidates (Jan 1-7):

   1. marketing@store.com (12 emails) - has List-Unsubscribe
   2. newsletter@blog.io (4 emails) - body link only
   3. updates@service.net (2 emails) - has List-Unsubscribe

   React with thumbs-up to any you'd like to unsubscribe from.
   ```
2. Agent watches for thumbs-up reactions on that message
3. On reaction, agent runs `email_unsubscribe` for that sender and replies with the result

## Ongoing Monitoring

A periodic task scans recent emails, identifies new senders not yet reviewed, and posts a new batch to the Zulip topic.

## Safety Constraints

- No delete: provider interface has no delete method
- Send constrained: `send_simple` enforces max body length (~50 chars), only "unsubscribe"-type content
- All actions logged via existing audit log
- Human approval required: nothing unsubscribes without a thumbs-up reaction

## State Persistence

JSON file on Fly.io volume (`/data/email_subscriptions.json`) tracks:
- Known senders and their status (active / unsubscribed / pending)
- Which date ranges have been scanned
- Unsubscribe method used and result

## Credentials

- Fastmail API token: `FASTMAIL_API_TOKEN` env var (+ `fly secrets set`)
- JMAP session endpoint: `https://api.fastmail.com/jmap/session`

## Future Extensions

- Gmail provider (Google REST API, same EmailProvider interface)
- Multiple account support
- More sophisticated subscription detection (beyond frequency-based)
