# Decompose email_scan into composable tools

## Problem

The `email_scan` MCP tool fetches up to 500 emails for a date range and returns them as a single formatted text blob. This exceeds the context window of smaller LLMs (the nanobot agent hit 32K tokens against an 8K limit scanning just 1-2 days of email). The monolithic design also violates the project's principle of preferring agent primitives over complex MCP tools.

## Solution

Replace `email_scan` with four small, composable tools that let the agent control pagination and drill into individual messages. The agent reasons about how to combine them rather than receiving a pre-aggregated report.

## New tools

### `email_accounts()`

- **Parameters**: none
- **Returns**: JSON list of configured account names, e.g. `["fastmail", "gmail"]`
- **Purpose**: Agent discovers what email accounts are available before searching

### `email_search(after, before?, folder?, account?, limit?, offset?)`

- **Parameters**:
  - `after` (str, required): Start date, ISO format (e.g. `"2026-04-05"`)
  - `before` (str, optional): End date, ISO format. Defaults to today.
  - `folder` (str, optional): Mailbox folder. Defaults to `"Inbox"`.
  - `account` (str, optional): Account name from `email_accounts()`. If omitted, searches all accounts (merged by date).
  - `limit` (int, optional): Max emails to return. Default 20, max 50.
  - `offset` (int, optional): Number of results to skip. Default 0.
- **Returns**: JSON object:
  ```json
  {
    "total": 142,
    "offset": 0,
    "limit": 20,
    "emails": [
      {
        "account": "fastmail",
        "message_id": "msg-abc",
        "sender": "news@example.com",
        "subject": "Newsletter #42",
        "date": "2026-04-05T10:30:00+00:00",
        "has_list_unsubscribe": true
      }
    ]
  }
  ```
- **Notes**: When searching all accounts, results are merged and sorted by date descending, then limit/offset applied to the merged set. The `account` field in each email tells the agent which account to use for follow-up calls. If `account` is provided but doesn't match a configured provider, return an error string (not an exception) so the agent can self-correct.

### `email_get_headers(account, message_id)`

- **Parameters**:
  - `account` (str, required): Account name (e.g. `"fastmail"`)
  - `message_id` (str, required): Message ID from `email_search` results
- **Returns**: JSON dict of headers:
  ```json
  {
    "From": "sender@example.com",
    "Subject": "Newsletter",
    "List-Unsubscribe": "<mailto:unsub@example.com>",
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"
  }
  ```
- **Notes**: Thin wrapper around existing `provider.get_headers()`. Only present headers are included. Returns an error string if `account` doesn't match a configured provider.

### `email_get_body(account, message_id)`

- **Parameters**:
  - `account` (str, required): Account name
  - `message_id` (str, required): Message ID from `email_search` results
- **Returns**: Message body as a string (HTML preferred, falls back to plain text)
- **Notes**: Thin wrapper around existing `provider.get_body()`. Returns an error string if `account` doesn't match a configured provider.

## Provider changes

### `EmailProvider.search()` signature

Current: `search(after, before, folder) -> list[EmailSummary]`

New: `search(after, before, folder, limit, offset) -> SearchResult`

Where `SearchResult` is a new dataclass:
```python
@dataclass
class SearchResult:
    emails: list[EmailSummary]
    total: int
```

### Fastmail implementation

JMAP `Email/query` natively supports `limit` and `position` (offset). Pass them through directly. For `total`, JMAP returns a `total` field in the query response.

### Gmail implementation

Gmail `messages.list` supports `maxResults` but uses opaque `pageToken` for pagination, not numeric offset. Approach:
- Fetch the message ID list with a reasonable cap (e.g. 500 IDs — this is cheap, no metadata)
- Slice the ID list by offset/limit
- Fetch metadata only for the sliced IDs (this is the expensive part)
- Return `total` as the length of the full ID list

## Removed

- `email_scan` tool — deleted entirely, not deprecated
- Formatted text report — agent handles presentation

## Agent workflow example

For "find political emails to unsubscribe from":

1. `email_accounts()` -> `["fastmail"]`
2. `email_search(after="2026-04-05", account="fastmail", limit=20)` -> 20 emails with senders/subjects
3. Agent identifies political-looking senders from subjects
4. `email_search(after="2026-04-05", account="fastmail", limit=20, offset=20)` -> next page if needed
5. `email_get_headers(account="fastmail", message_id="msg-xyz")` -> get unsubscribe link for specific message

Each step fits comfortably in 8K context.

## Testing

- Unit tests for each new MCP tool, mocking providers (same pattern as existing `test_email_tools.py`)
- Unit tests for updated `search()` with limit/offset in both Fastmail and Gmail providers
- Tests for `email_accounts` with various provider configurations (one, both, none)
- Tests for `email_get_headers` / `email_get_body` routing to correct provider by account name
- Tests for multi-account `email_search` merge behavior
- Existing `email_scan` tests removed
