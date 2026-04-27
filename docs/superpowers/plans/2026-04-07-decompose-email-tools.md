# Decompose email_scan into Composable Tools — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the monolithic `email_scan` MCP tool with four composable tools (`email_accounts`, `email_search`, `email_get_headers`, `email_get_body`) that let the agent control pagination and stay within small context windows.

**Architecture:** Add a `SearchResult` dataclass to the provider layer and update both Fastmail/Gmail providers to support `limit`/`offset` in `search()`. Then rewrite `tools.py` to expose four small tools that delegate to providers by account name. Remove `email_scan` entirely.

**Tech Stack:** Python 3.12+, FastMCP, httpx, pytest + pytest-asyncio + pytest-httpx

**Spec:** `docs/superpowers/specs/2026-04-07-decompose-email-tools-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `personal_agent/email/provider.py` | Modify | Add `SearchResult` dataclass, update `search()` ABC signature |
| `personal_agent/email/fastmail.py` | Modify | Implement paginated `search()` returning `SearchResult` |
| `personal_agent/email/gmail.py` | Modify | Implement paginated `search()` returning `SearchResult` |
| `personal_agent/email/tools.py` | Rewrite | Remove `email_scan`, add 4 new MCP tools + `_get_provider()` helper |
| `tests/test_email_tools.py` | Rewrite | Tests for all 4 new tools, remove `email_scan` tests |
| `tests/test_fastmail.py` | Modify | Update search tests for new signature + pagination |
| `tests/test_gmail.py` | Create | Search pagination tests for Gmail provider |

---

### Task 1: Add `SearchResult` to provider and update ABC

**Files:**
- Modify: `personal_agent/email/provider.py:11-44`

- [ ] **Step 1: Add `SearchResult` dataclass after `EmailSummary`**

In `personal_agent/email/provider.py`, add after the `EmailSummary` class (after line 20):

```python
@dataclass
class SearchResult:
    """Paginated search result."""

    emails: list[EmailSummary]
    total: int
```

- [ ] **Step 2: Update `search()` ABC signature**

In `personal_agent/email/provider.py`, change the `search` abstract method (lines 36-44) to:

```python
@abstractmethod
async def search(
    self,
    after: date,
    before: date,
    folder: str = "Inbox",
    limit: int = 20,
    offset: int = 0,
) -> SearchResult:
    """Return summaries of messages in *folder* within the date range."""
    ...
```

- [ ] **Step 3: Verify the module imports cleanly**

Run: `python -c "from personal_agent.email.provider import EmailProvider, EmailSummary, SearchResult; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add personal_agent/email/provider.py
git commit -m "refactor: add SearchResult dataclass and paginated search() ABC"
```

---

### Task 2: Update Fastmail provider search with pagination

**Files:**
- Modify: `tests/test_fastmail.py:95-191`
- Modify: `personal_agent/email/fastmail.py:94-164`

- [ ] **Step 1: Write failing test for paginated search**

In `tests/test_fastmail.py`, add to the existing `TestSearch` class, after the existing tests. Also add `SearchResult` to any imports if needed:

```python
from personal_agent.email.provider import SearchResult

# Add these tests inside class TestSearch:

async def test_search_returns_search_result(self, httpx_mock, provider):
    """search() returns SearchResult with total count."""
    _add_session_mock(httpx_mock)
    httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)
    httpx_mock.add_response(
        url=FAKE_API_URL,
        json={
            "methodResponses": [
                ["Email/query", {"ids": ["msg-1", "msg-2", "msg-3"], "total": 3}, "q0"],
                [
                    "Email/get",
                    {
                        "list": [
                            {
                                "id": "msg-1",
                                "from": [{"email": "a@example.com"}],
                                "subject": "A",
                                "receivedAt": "2026-03-01T10:00:00Z",
                                "header:List-Unsubscribe": None,
                            },
                            {
                                "id": "msg-2",
                                "from": [{"email": "b@example.com"}],
                                "subject": "B",
                                "receivedAt": "2026-03-02T10:00:00Z",
                                "header:List-Unsubscribe": None,
                            },
                            {
                                "id": "msg-3",
                                "from": [{"email": "c@example.com"}],
                                "subject": "C",
                                "receivedAt": "2026-03-03T10:00:00Z",
                                "header:List-Unsubscribe": None,
                            },
                        ]
                    },
                    "g0",
                ],
            ]
        },
    )

    result = await provider.search(after=date(2026, 3, 1), before=date(2026, 3, 7))
    assert isinstance(result, SearchResult)
    assert result.total == 3
    assert len(result.emails) == 3

async def test_search_respects_limit_and_offset(self, httpx_mock, provider):
    """limit and offset are passed to JMAP Email/query."""
    _add_session_mock(httpx_mock)
    httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)
    httpx_mock.add_response(
        url=FAKE_API_URL,
        json={
            "methodResponses": [
                ["Email/query", {"ids": ["msg-2"], "total": 3}, "q0"],
                [
                    "Email/get",
                    {
                        "list": [
                            {
                                "id": "msg-2",
                                "from": [{"email": "b@example.com"}],
                                "subject": "B",
                                "receivedAt": "2026-03-02T10:00:00Z",
                                "header:List-Unsubscribe": None,
                            },
                        ]
                    },
                    "g0",
                ],
            ]
        },
    )

    result = await provider.search(
        after=date(2026, 3, 1), before=date(2026, 3, 7), limit=1, offset=1
    )
    assert result.total == 3
    assert len(result.emails) == 1
    assert result.emails[0].message_id == "msg-2"

    # Verify the JMAP request included limit and position
    import json
    api_requests = [r for r in httpx_mock.get_requests() if r.url == FAKE_API_URL]
    body = json.loads(api_requests[1].content)
    query_params = body["methodCalls"][0][1]
    assert query_params["limit"] == 1
    assert query_params["position"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_fastmail.py::TestSearch::test_search_returns_search_result tests/test_fastmail.py::TestSearch::test_search_respects_limit_and_offset -v`
Expected: FAIL — `search()` returns `list[EmailSummary]`, not `SearchResult`

- [ ] **Step 3: Update existing Fastmail tests for new return type**

The existing `test_search_with_date_filtering` (line 96) asserts `len(results) == 2` and `results[0].message_id`. Update to use `result.emails`:

```python
async def test_search_with_date_filtering(self, httpx_mock, provider):
    """Search returns EmailSummary objects with correct fields."""
    _add_session_mock(httpx_mock)
    httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)
    httpx_mock.add_response(
        url=FAKE_API_URL,
        json={
            "methodResponses": [
                ["Email/query", {"ids": ["msg-1", "msg-2"], "total": 2}, "q0"],
                [
                    "Email/get",
                    {
                        "list": [
                            {
                                "id": "msg-1",
                                "from": [{"email": "alice@example.com"}],
                                "subject": "Newsletter",
                                "receivedAt": "2026-03-01T10:00:00Z",
                                "header:List-Unsubscribe": "<mailto:unsub@example.com>",
                            },
                            {
                                "id": "msg-2",
                                "from": [{"email": "bob@example.com"}],
                                "subject": "Hello",
                                "receivedAt": "2026-03-02T14:30:00Z",
                                "header:List-Unsubscribe": None,
                            },
                        ]
                    },
                    "g0",
                ],
            ]
        },
    )

    result = await provider.search(after=date(2026, 3, 1), before=date(2026, 3, 7))
    assert len(result.emails) == 2
    assert result.total == 2
    assert result.emails[0].message_id == "msg-1"
    assert result.emails[0].sender == "alice@example.com"
    assert result.emails[0].subject == "Newsletter"
    assert result.emails[0].has_list_unsubscribe is True
    assert result.emails[1].message_id == "msg-2"
    assert result.emails[1].has_list_unsubscribe is False
```

The existing `test_search_unknown_folder_returns_empty` (line 152) asserts `results == []`. Update:

```python
async def test_search_unknown_folder_returns_empty(self, httpx_mock, provider):
    _add_session_mock(httpx_mock)
    httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)

    result = await provider.search(
        after=date(2026, 3, 1), before=date(2026, 3, 7), folder="NonExistent"
    )
    assert result.emails == []
    assert result.total == 0
```

The `test_search_sends_correct_filter` (line 163) doesn't check the return value, but verify it still passes after the signature change.

The `test_all_requests_go_through_proxy` (line 528) asserts `len(results) == 1` and `results[0].sender`. Update:

```python
# In class TestProxyRouting, update the assertion at the end of test_all_requests_go_through_proxy:
# Change:
#   assert len(results) == 1
#   assert results[0].sender == "proxy@example.com"
# To:
    assert len(result.emails) == 1
    assert result.emails[0].sender == "proxy@example.com"
```

Also update the JMAP response in that test to include `"total": 1` in the Email/query response.

- [ ] **Step 4: Implement paginated search in Fastmail provider**

In `personal_agent/email/fastmail.py`, update the import and `search()` method:

Add `SearchResult` to the import from provider:
```python
from personal_agent.email.provider import EmailProvider, EmailSummary, SearchResult
```

Replace the `search()` method (lines 94-164):

```python
async def search(
    self,
    after: date,
    before: date,
    folder: str = "Inbox",
    limit: int = 20,
    offset: int = 0,
) -> SearchResult:
    """Search for emails in *folder* within the given date range."""
    await self._ensure_session()

    mailbox_id = await self._resolve_mailbox_id(folder)
    if mailbox_id is None:
        return SearchResult(emails=[], total=0)

    filter_condition: dict[str, Any] = {
        "inMailbox": mailbox_id,
        "after": f"{after.isoformat()}T00:00:00Z",
        "before": f"{before.isoformat()}T00:00:00Z",
    }

    responses = await self._jmap_request([
        [
            "Email/query",
            {
                "accountId": self._account_id,
                "filter": filter_condition,
                "sort": [{"property": "receivedAt", "isAscending": False}],
                "limit": limit,
                "position": offset,
            },
            "q0",
        ],
        [
            "Email/get",
            {
                "accountId": self._account_id,
                "#ids": {
                    "resultOf": "q0",
                    "name": "Email/query",
                    "path": "/ids",
                },
                "properties": [
                    "id",
                    "from",
                    "subject",
                    "receivedAt",
                    "header:List-Unsubscribe",
                ],
            },
            "g0",
        ],
    ])

    total = responses[0][1].get("total", 0)
    emails = responses[1][1]["list"]
    results: list[EmailSummary] = []
    for email in emails:
        sender_list = email.get("from") or []
        sender = sender_list[0].get("email", "") if sender_list else ""
        received_at = email.get("receivedAt", "")
        dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
        list_unsub = email.get("header:List-Unsubscribe") or ""
        results.append(
            EmailSummary(
                message_id=email["id"],
                sender=sender,
                subject=email.get("subject", ""),
                date=dt,
                has_list_unsubscribe=bool(list_unsub),
                list_unsubscribe=list_unsub.strip(),
            )
        )
    return SearchResult(emails=results, total=total)
```

- [ ] **Step 5: Run all Fastmail tests**

Run: `uv run pytest tests/test_fastmail.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add personal_agent/email/fastmail.py tests/test_fastmail.py
git commit -m "feat: paginated search() in Fastmail provider with limit/offset"
```

---

### Task 3: Update Gmail provider search with pagination

**Files:**
- Create: `tests/test_gmail.py`
- Modify: `personal_agent/email/gmail.py:111-188`

- [ ] **Step 1: Write failing tests for Gmail paginated search**

Create `tests/test_gmail.py`:

```python
"""Tests for the Gmail REST API provider."""

from __future__ import annotations

from datetime import date

import httpx
import pytest

from personal_agent.email.gmail import GmailProvider
from personal_agent.email.provider import SearchResult

FAKE_PROXY_BASE = "http://polynumeral-cred-proxy.flycast:8080/gmail"
FAKE_MESSAGES_URL = f"{FAKE_PROXY_BASE}/gmail/v1/users/me/messages"


@pytest.fixture
def provider():
    return GmailProvider(api_base=FAKE_PROXY_BASE)


def _message_url(msg_id: str) -> str:
    return f"{FAKE_MESSAGES_URL}/{msg_id}"


def _stub_message(msg_id: str, sender: str, subject: str, internal_date_ms: int = 1709290800000, list_unsub: str | None = None):
    """Build a Gmail message response dict."""
    headers = [
        {"name": "From", "value": sender},
        {"name": "Subject", "value": subject},
        {"name": "Date", "value": "Sat, 01 Mar 2026 10:00:00 +0000"},
    ]
    if list_unsub is not None:
        headers.append({"name": "List-Unsubscribe", "value": list_unsub})
    return {
        "id": msg_id,
        "internalDate": str(internal_date_ms),
        "payload": {"headers": headers},
    }


class TestSearch:
    async def test_search_returns_search_result(self, httpx_mock, provider):
        """search() returns SearchResult with total count."""
        httpx_mock.add_response(
            url=FAKE_MESSAGES_URL,
            json={"messages": [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}]},
        )
        for msg_id, sender in [("m1", "a@x.com"), ("m2", "b@x.com"), ("m3", "c@x.com")]:
            httpx_mock.add_response(
                url=_message_url(msg_id),
                json=_stub_message(msg_id, sender, f"Subject {msg_id}"),
            )

        result = await provider.search(after=date(2026, 3, 1), before=date(2026, 3, 7))
        assert isinstance(result, SearchResult)
        assert result.total == 3
        assert len(result.emails) == 3

    async def test_search_respects_limit_and_offset(self, httpx_mock, provider):
        """Only metadata for the sliced IDs should be fetched."""
        httpx_mock.add_response(
            url=FAKE_MESSAGES_URL,
            json={"messages": [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}]},
        )
        # Only m2 should be fetched (offset=1, limit=1)
        httpx_mock.add_response(
            url=_message_url("m2"),
            json=_stub_message("m2", "b@x.com", "Subject B"),
        )

        result = await provider.search(
            after=date(2026, 3, 1), before=date(2026, 3, 7), limit=1, offset=1
        )
        assert result.total == 3
        assert len(result.emails) == 1
        assert result.emails[0].message_id == "m2"

        # Verify only 2 requests: list + 1 metadata fetch (not 3 metadata fetches)
        requests = httpx_mock.get_requests()
        assert len(requests) == 2

    async def test_search_empty_results(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=FAKE_MESSAGES_URL,
            json={},
        )

        result = await provider.search(after=date(2026, 3, 1), before=date(2026, 3, 7))
        assert result.total == 0
        assert result.emails == []

    async def test_search_offset_beyond_results(self, httpx_mock, provider):
        """Offset past the end returns empty emails but correct total."""
        httpx_mock.add_response(
            url=FAKE_MESSAGES_URL,
            json={"messages": [{"id": "m1"}]},
        )

        result = await provider.search(
            after=date(2026, 3, 1), before=date(2026, 3, 7), offset=5
        )
        assert result.total == 1
        assert result.emails == []


class TestConstructor:
    def test_raises_if_no_api_base(self):
        with pytest.raises(ValueError, match="api_base must be provided"):
            GmailProvider(api_base="")

    def test_strips_trailing_slash(self):
        p = GmailProvider(api_base="http://proxy:8080/gmail/")
        assert p._api_base == "http://proxy:8080/gmail"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_gmail.py -v`
Expected: FAIL — `search()` returns `list`, not `SearchResult`

- [ ] **Step 3: Implement paginated search in Gmail provider**

In `personal_agent/email/gmail.py`, update the import:
```python
from personal_agent.email.provider import EmailProvider, EmailSummary, SearchResult
```

Replace the `search()` method (lines 111-188):

```python
async def search(
    self,
    after: date,
    before: date,
    folder: str = "Inbox",
    limit: int = 20,
    offset: int = 0,
) -> SearchResult:
    """Search for emails in *folder* within the given date range."""
    import asyncio

    label_id = self._resolve_label_id(folder)

    # Gmail search query uses YYYY/MM/DD format
    q = f"after:{after.strftime('%Y/%m/%d')} before:{before.strftime('%Y/%m/%d')}"

    params: dict[str, Any] = {
        "q": q,
        "labelIds": label_id,
        "maxResults": 500,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            self._url("/messages"),
            headers=self._headers(),
            params=params,
        )
        resp.raise_for_status()
        data = resp.json()

    message_stubs = data.get("messages", [])
    total = len(message_stubs)
    if not message_stubs:
        return SearchResult(emails=[], total=0)

    # Slice by offset/limit — only fetch metadata for the page we need
    page_stubs = message_stubs[offset : offset + limit]
    if not page_stubs:
        return SearchResult(emails=[], total=total)

    sem = asyncio.Semaphore(5)

    async def _fetch_one(client: httpx.AsyncClient, msg_id: str) -> EmailSummary:
        async with sem:
            resp = await client.get(
                self._url(f"/messages/{msg_id}"),
                headers=self._headers(),
                params={"format": "metadata", "metadataHeaders": [
                    "From", "Subject", "Date", "List-Unsubscribe",
                ]},
            )
            resp.raise_for_status()
            msg = resp.json()

        headers = msg.get("payload", {}).get("headers", [])
        from_header = self._find_header(headers, "From") or ""
        subject = self._find_header(headers, "Subject") or ""
        list_unsub = self._find_header(headers, "List-Unsubscribe") or ""

        sender = from_header
        if "<" in from_header and ">" in from_header:
            sender = from_header.split("<")[1].split(">")[0]

        internal_date_ms = int(msg.get("internalDate", "0"))
        dt = datetime.fromtimestamp(
            internal_date_ms / 1000, tz=timezone.utc
        )

        return EmailSummary(
            message_id=msg_id,
            sender=sender,
            subject=subject,
            date=dt,
            has_list_unsubscribe=bool(list_unsub),
            list_unsubscribe=list_unsub,
        )

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[_fetch_one(client, stub["id"]) for stub in page_stubs]
        )

    return SearchResult(emails=list(results), total=total)
```

- [ ] **Step 4: Run Gmail tests**

Run: `uv run pytest tests/test_gmail.py -v`
Expected: All pass

- [ ] **Step 5: Run all tests to check nothing else broke**

Run: `uv run pytest -v`
Expected: Fastmail tests may fail because `test_email_tools.py` still uses old `email_scan` which calls `provider.search()` returning old type. That's expected — we'll fix it in Task 4.

- [ ] **Step 6: Commit**

```bash
git add personal_agent/email/gmail.py tests/test_gmail.py
git commit -m "feat: paginated search() in Gmail provider with limit/offset"
```

---

### Task 4: Rewrite tools.py — remove email_scan, add new tools

**Files:**
- Rewrite: `personal_agent/email/tools.py`
- Rewrite: `tests/test_email_tools.py`

- [ ] **Step 1: Write failing tests for all four new tools**

Rewrite `tests/test_email_tools.py` entirely:

```python
"""Tests for personal_agent.email.tools MCP server."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from personal_agent.email.provider import EmailSummary, SearchResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_email(
    sender: str,
    subject: str = "Test",
    msg_id: str = "msg-1",
    has_unsub: bool = False,
    list_unsub: str = "",
    dt: datetime | None = None,
) -> EmailSummary:
    return EmailSummary(
        message_id=msg_id,
        sender=sender,
        subject=subject,
        date=dt or datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc),
        has_list_unsubscribe=has_unsub,
        list_unsubscribe=list_unsub,
    )


def _make_search_result(emails: list[EmailSummary], total: int | None = None) -> SearchResult:
    return SearchResult(emails=emails, total=total if total is not None else len(emails))


def _mock_single_provider(mock_provider):
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_provider)],
    )


def _mock_multi_providers(mock_fastmail, mock_gmail):
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_fastmail), ("gmail", mock_gmail)],
    )


# ---------------------------------------------------------------------------
# email_accounts tests
# ---------------------------------------------------------------------------


class TestEmailAccounts:
    async def test_returns_single_account(self):
        from personal_agent.email.tools import email_accounts

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = json.loads(await email_accounts())
        assert result == ["fastmail"]

    async def test_returns_multiple_accounts(self):
        from personal_agent.email.tools import email_accounts

        mock_fm = AsyncMock()
        mock_gm = AsyncMock()
        with _mock_multi_providers(mock_fm, mock_gm):
            result = json.loads(await email_accounts())
        assert result == ["fastmail", "gmail"]


# ---------------------------------------------------------------------------
# email_search tests
# ---------------------------------------------------------------------------


class TestEmailSearch:
    async def test_search_single_account(self):
        from personal_agent.email.tools import email_search

        emails = [
            _make_email("a@example.com", "Subject A", "m1"),
            _make_email("b@example.com", "Subject B", "m2"),
        ]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result(emails))

        with _mock_single_provider(mock_provider):
            raw = await email_search("2026-03-01", account="fastmail")

        result = json.loads(raw)
        assert result["total"] == 2
        assert len(result["emails"]) == 2
        assert result["emails"][0]["account"] == "fastmail"
        assert result["emails"][0]["sender"] == "a@example.com"

    async def test_search_all_accounts_merges_by_date(self):
        from personal_agent.email.tools import email_search

        fm_emails = [_make_email("fm@x.com", "FM", "fm1", dt=datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc))]
        gm_emails = [_make_email("gm@x.com", "GM", "gm1", dt=datetime(2026, 3, 6, 12, 0, tzinfo=timezone.utc))]

        mock_fm = AsyncMock()
        mock_fm.search = AsyncMock(return_value=_make_search_result(fm_emails))
        mock_gm = AsyncMock()
        mock_gm.search = AsyncMock(return_value=_make_search_result(gm_emails))

        with _mock_multi_providers(mock_fm, mock_gm):
            raw = await email_search("2026-03-01")

        result = json.loads(raw)
        assert result["total"] == 2
        # Sorted by date descending — gmail email (Mar 6) comes first
        assert result["emails"][0]["account"] == "gmail"
        assert result["emails"][1]["account"] == "fastmail"

    async def test_search_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_search("2026-03-01", account="nonexistent")

        assert "error" in result.lower()
        assert "nonexistent" in result.lower()

    async def test_search_respects_limit(self):
        from personal_agent.email.tools import email_search

        emails = [_make_email(f"s{i}@x.com", f"S{i}", f"m{i}") for i in range(5)]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result(emails, total=5))

        with _mock_single_provider(mock_provider):
            raw = await email_search("2026-03-01", account="fastmail", limit=2)

        # limit is passed to the provider, so the mock returns all 5
        # but the tool should pass limit to provider.search()
        mock_provider.search.assert_called_once()
        call_kwargs = mock_provider.search.call_args
        assert call_kwargs.kwargs.get("limit") == 2 or call_kwargs[1].get("limit") == 2

    async def test_search_clamps_limit_to_50(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result([]))

        with _mock_single_provider(mock_provider):
            await email_search("2026-03-01", account="fastmail", limit=100)

        call_kwargs = mock_provider.search.call_args
        passed_limit = call_kwargs.kwargs.get("limit", call_kwargs[1].get("limit"))
        assert passed_limit == 50

    async def test_search_no_results(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result([]))

        with _mock_single_provider(mock_provider):
            raw = await email_search("2026-03-01", account="fastmail")

        result = json.loads(raw)
        assert result["total"] == 0
        assert result["emails"] == []


# ---------------------------------------------------------------------------
# email_get_headers tests
# ---------------------------------------------------------------------------


class TestEmailGetHeaders:
    async def test_returns_headers_json(self):
        from personal_agent.email.tools import email_get_headers

        mock_provider = AsyncMock()
        mock_provider.get_headers = AsyncMock(return_value={
            "From": "alice@example.com",
            "Subject": "Newsletter",
            "List-Unsubscribe": "<mailto:unsub@example.com>",
        })

        with _mock_single_provider(mock_provider):
            raw = await email_get_headers("fastmail", "msg-1")

        result = json.loads(raw)
        assert result["From"] == "alice@example.com"
        assert result["List-Unsubscribe"] == "<mailto:unsub@example.com>"

    async def test_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_get_headers

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_get_headers("nonexistent", "msg-1")

        assert "error" in result.lower()

    async def test_routes_to_correct_provider(self):
        from personal_agent.email.tools import email_get_headers

        mock_fm = AsyncMock()
        mock_fm.get_headers = AsyncMock(return_value={"From": "fm@x.com"})
        mock_gm = AsyncMock()
        mock_gm.get_headers = AsyncMock(return_value={"From": "gm@x.com"})

        with _mock_multi_providers(mock_fm, mock_gm):
            raw = await email_get_headers("gmail", "msg-1")

        result = json.loads(raw)
        assert result["From"] == "gm@x.com"
        mock_gm.get_headers.assert_called_once_with("msg-1")
        mock_fm.get_headers.assert_not_called()


# ---------------------------------------------------------------------------
# email_get_body tests
# ---------------------------------------------------------------------------


class TestEmailGetBody:
    async def test_returns_body_string(self):
        from personal_agent.email.tools import email_get_body

        mock_provider = AsyncMock()
        mock_provider.get_body = AsyncMock(return_value="<p>Hello world</p>")

        with _mock_single_provider(mock_provider):
            result = await email_get_body("fastmail", "msg-1")

        assert result == "<p>Hello world</p>"

    async def test_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_get_body

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_get_body("nonexistent", "msg-1")

        assert "error" in result.lower()

    async def test_routes_to_correct_provider(self):
        from personal_agent.email.tools import email_get_body

        mock_fm = AsyncMock()
        mock_fm.get_body = AsyncMock(return_value="FM body")
        mock_gm = AsyncMock()
        mock_gm.get_body = AsyncMock(return_value="GM body")

        with _mock_multi_providers(mock_fm, mock_gm):
            result = await email_get_body("gmail", "msg-1")

        assert result == "GM body"
        mock_gm.get_body.assert_called_once_with("msg-1")
        mock_fm.get_body.assert_not_called()


# ---------------------------------------------------------------------------
# _get_providers() tests (unchanged behavior)
# ---------------------------------------------------------------------------


class TestGetProviders:
    def test_no_providers_raises(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict("os.environ", {"FASTMAIL_API_BASE": "", "GMAIL_API_BASE": ""}, clear=False):
            with pytest.raises(RuntimeError, match="No email providers configured"):
                _get_providers()

    def test_fastmail_only(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict(
            "os.environ",
            {"FASTMAIL_API_BASE": "http://proxy/fastmail", "GMAIL_API_BASE": ""},
            clear=False,
        ):
            providers = _get_providers()
            assert len(providers) == 1
            assert providers[0][0] == "fastmail"

    def test_both_providers(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict(
            "os.environ",
            {
                "FASTMAIL_API_BASE": "http://proxy/fastmail",
                "GMAIL_API_BASE": "http://proxy/gmail",
            },
            clear=False,
        ):
            providers = _get_providers()
            assert len(providers) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_email_tools.py -v`
Expected: FAIL — `email_accounts`, `email_search`, etc. don't exist yet

- [ ] **Step 3: Rewrite tools.py with all four new tools**

Replace `personal_agent/email/tools.py` entirely:

```python
"""Email MCP tools -- FastMCP server exposing composable email tools."""

from __future__ import annotations

import json
import os
from datetime import date

from mcp.server.fastmcp import FastMCP

from personal_agent.email.fastmail import FastmailProvider
from personal_agent.email.gmail import GmailProvider
from personal_agent.email.provider import EmailProvider

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


def _get_provider(account: str) -> EmailProvider | None:
    """Look up a single provider by account name. Returns None if not found."""
    for name, provider in _get_providers():
        if name == account:
            return provider
    return None


@mcp.tool()
async def email_accounts() -> str:
    """List configured email account names.

    Returns a JSON array of account names, e.g. ["fastmail", "gmail"].
    Use these names with email_search, email_get_headers, and email_get_body.
    """
    providers = _get_providers()
    return json.dumps([name for name, _ in providers])


@mcp.tool()
async def email_search(
    after: str,
    before: str = "",
    folder: str = "Inbox",
    account: str = "",
    limit: int = 20,
    offset: int = 0,
) -> str:
    """Search emails in a date range with pagination.

    Parameters
    ----------
    after:
        Start date (ISO format, e.g. "2026-03-01").
    before:
        End date (ISO format, e.g. "2026-03-26"). Defaults to today.
    folder:
        Mailbox folder to scan (default "Inbox").
    account:
        Account name from email_accounts(). If empty, searches all accounts.
    limit:
        Max emails to return (default 20, max 50).
    offset:
        Number of results to skip (default 0).

    Returns JSON with total count and email summaries.
    """
    limit = min(limit, 50)
    after_date = date.fromisoformat(after)
    before_date = date.fromisoformat(before) if before else date.today()

    if account:
        provider = _get_provider(account)
        if provider is None:
            names = [n for n, _ in _get_providers()]
            return f"Error: unknown account '{account}'. Available accounts: {names}"
        result = await provider.search(after_date, before_date, folder, limit=limit, offset=offset)
        emails_out = [
            {
                "account": account,
                "message_id": e.message_id,
                "sender": e.sender,
                "subject": e.subject,
                "date": e.date.isoformat(),
                "has_list_unsubscribe": e.has_list_unsubscribe,
            }
            for e in result.emails
        ]
        return json.dumps({"total": result.total, "offset": offset, "limit": limit, "emails": emails_out})

    # Search all accounts, merge by date descending
    all_tagged: list[tuple[str, object]] = []
    total = 0
    for name, provider in _get_providers():
        # Fetch enough to cover the requested window after merge
        result = await provider.search(after_date, before_date, folder, limit=offset + limit, offset=0)
        total += result.total
        for e in result.emails:
            all_tagged.append((name, e))

    # Sort merged results by date descending
    all_tagged.sort(key=lambda x: x[1].date, reverse=True)

    # Apply offset/limit to the merged set
    page = all_tagged[offset : offset + limit]

    emails_out = [
        {
            "account": acct,
            "message_id": e.message_id,
            "sender": e.sender,
            "subject": e.subject,
            "date": e.date.isoformat(),
            "has_list_unsubscribe": e.has_list_unsubscribe,
        }
        for acct, e in page
    ]
    return json.dumps({"total": total, "offset": offset, "limit": limit, "emails": emails_out})


@mcp.tool()
async def email_get_headers(account: str, message_id: str) -> str:
    """Get headers for a specific email message.

    Parameters
    ----------
    account:
        Account name from email_accounts().
    message_id:
        Message ID from email_search results.

    Returns JSON dict of headers (From, Subject, List-Unsubscribe, etc.).
    """
    provider = _get_provider(account)
    if provider is None:
        names = [n for n, _ in _get_providers()]
        return f"Error: unknown account '{account}'. Available accounts: {names}"
    headers = await provider.get_headers(message_id)
    return json.dumps(headers)


@mcp.tool()
async def email_get_body(account: str, message_id: str) -> str:
    """Get the body of a specific email message.

    Parameters
    ----------
    account:
        Account name from email_accounts().
    message_id:
        Message ID from email_search results.

    Returns the message body (HTML preferred, falls back to plain text).
    """
    provider = _get_provider(account)
    if provider is None:
        names = [n for n, _ in _get_providers()]
        return f"Error: unknown account '{account}'. Available accounts: {names}"
    return await provider.get_body(message_id)


def main() -> None:
    """Run the email MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all tests**

Run: `uv run pytest -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add personal_agent/email/tools.py tests/test_email_tools.py
git commit -m "feat: replace email_scan with composable email_accounts/search/get_headers/get_body tools"
```

---

### Task 5: Final verification and cleanup

**Files:** None new — cross-cutting check

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest -v`
Expected: All tests pass across `test_email_tools.py`, `test_fastmail.py`, `test_gmail.py`

- [ ] **Step 2: Verify the MCP server starts**

Run: `python -c "from personal_agent.email.tools import mcp; print('Tools:', [t.name for t in mcp._tools.values()])"`
Expected: `Tools: ['email_accounts', 'email_search', 'email_get_headers', 'email_get_body']`

(The exact attribute for listing tools may vary by FastMCP version — adjust if needed. The point is to verify 4 tools are registered and `email_scan` is gone.)

- [ ] **Step 3: Commit any final fixes**

If any adjustments were needed, commit them:
```bash
git add -u
git commit -m "fix: final adjustments from integration testing"
```
