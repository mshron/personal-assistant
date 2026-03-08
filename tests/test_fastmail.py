"""Tests for the Fastmail JMAP provider."""

from __future__ import annotations

from datetime import date

import httpx
import pytest

from personal_agent.email.fastmail import FastmailProvider

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

FAKE_TOKEN = "fmtok-test-token"
FAKE_ACCOUNT_ID = "u1234"
FAKE_API_URL = "https://api.fastmail.com/jmap/api"
FAKE_PROXY_BASE = "http://polynumeral-cred-proxy.flycast:8080/fastmail"
FAKE_PROXY_SESSION_URL = f"{FAKE_PROXY_BASE}/jmap/session"
FAKE_PROXY_API_URL = f"{FAKE_PROXY_BASE}/jmap/api"

SESSION_RESPONSE = {
    "primaryAccounts": {"urn:ietf:params:jmap:mail": FAKE_ACCOUNT_ID},
    "apiUrl": FAKE_API_URL,
}

MAILBOX_RESPONSE = {
    "methodResponses": [
        [
            "Mailbox/get",
            {
                "accountId": FAKE_ACCOUNT_ID,
                "list": [
                    {"id": "mb-inbox", "name": "Inbox"},
                    {"id": "mb-trash", "name": "Trash"},
                ],
            },
            "mb0",
        ]
    ]
}


@pytest.fixture
def provider():
    return FastmailProvider(token=FAKE_TOKEN)


@pytest.fixture
def proxy_provider():
    return FastmailProvider(api_base=FAKE_PROXY_BASE)


def _add_session_mock(httpx_mock):
    """Register the session endpoint mock (direct mode)."""
    httpx_mock.add_response(
        url="https://api.fastmail.com/jmap/session",
        json=SESSION_RESPONSE,
    )


def _add_proxy_session_mock(httpx_mock):
    """Register the session endpoint mock (proxy mode)."""
    httpx_mock.add_response(
        url=FAKE_PROXY_SESSION_URL,
        json=SESSION_RESPONSE,
    )


# ---------------------------------------------------------------------------
# Session discovery
# ---------------------------------------------------------------------------


class TestSessionDiscovery:
    async def test_discovers_account_and_api_url(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)

        await provider._ensure_session()

        assert provider._account_id == FAKE_ACCOUNT_ID
        assert provider._api_url == FAKE_API_URL

    async def test_session_cached_after_first_call(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)

        await provider._ensure_session()
        await provider._ensure_session()

        # Only one request should have been made.
        requests = httpx_mock.get_requests()
        assert len(requests) == 1

    async def test_session_failure_raises(self, httpx_mock, provider):
        httpx_mock.add_response(
            url="https://api.fastmail.com/jmap/session",
            status_code=401,
        )
        with pytest.raises(httpx.HTTPStatusError):
            await provider._ensure_session()


# ---------------------------------------------------------------------------
# search()
# ---------------------------------------------------------------------------


class TestSearch:
    async def test_search_with_date_filtering(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)

        # First JMAP call: Mailbox/get to resolve folder.
        httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)

        # Second JMAP call: Email/query + Email/get.
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/query",
                        {"ids": ["msg-1", "msg-2"]},
                        "q0",
                    ],
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

        results = await provider.search(
            after=date(2026, 3, 1),
            before=date(2026, 3, 7),
            folder="Inbox",
        )

        assert len(results) == 2
        assert results[0].message_id == "msg-1"
        assert results[0].sender == "alice@example.com"
        assert results[0].subject == "Newsletter"
        assert results[0].has_list_unsubscribe is True
        assert results[1].message_id == "msg-2"
        assert results[1].has_list_unsubscribe is False

    async def test_search_unknown_folder_returns_empty(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)

        results = await provider.search(
            after=date(2026, 3, 1),
            before=date(2026, 3, 7),
            folder="NonExistent",
        )
        assert results == []

    async def test_search_sends_correct_filter(self, httpx_mock, provider):
        """Verify the filter condition includes date range and mailbox."""
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(url=FAKE_API_URL, json=MAILBOX_RESPONSE)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    ["Email/query", {"ids": []}, "q0"],
                    ["Email/get", {"list": []}, "g0"],
                ]
            },
        )

        await provider.search(
            after=date(2026, 3, 1),
            before=date(2026, 3, 7),
        )

        # The third request is the Email/query + Email/get call (1=session, 2=mailbox, 3=query).
        api_requests = [r for r in httpx_mock.get_requests() if r.url == FAKE_API_URL]
        assert len(api_requests) == 2
        import json

        body = json.loads(api_requests[1].content)
        filter_cond = body["methodCalls"][0][1]["filter"]
        assert filter_cond["inMailbox"] == "mb-inbox"
        assert "2026-03-01" in filter_cond["after"]
        assert "2026-03-07" in filter_cond["before"]


# ---------------------------------------------------------------------------
# get_headers()
# ---------------------------------------------------------------------------


class TestGetHeaders:
    async def test_returns_list_unsubscribe_headers(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "msg-1",
                                    "header:List-Unsubscribe": " <mailto:unsub@example.com> ",
                                    "header:List-Unsubscribe-Post": " List-Unsubscribe=One-Click ",
                                    "header:From": " alice@example.com ",
                                    "header:Subject": " Newsletter ",
                                }
                            ]
                        },
                        "h0",
                    ]
                ]
            },
        )

        headers = await provider.get_headers("msg-1")

        assert headers["List-Unsubscribe"] == "<mailto:unsub@example.com>"
        assert headers["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
        assert headers["From"] == "alice@example.com"
        assert headers["Subject"] == "Newsletter"

    async def test_missing_message_returns_empty(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={"methodResponses": [["Email/get", {"list": []}, "h0"]]},
        )

        headers = await provider.get_headers("nonexistent")
        assert headers == {}

    async def test_partial_headers(self, httpx_mock, provider):
        """Only present headers are returned."""
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "msg-1",
                                    "header:List-Unsubscribe": None,
                                    "header:List-Unsubscribe-Post": None,
                                    "header:From": " sender@x.com ",
                                    "header:Subject": " Hi ",
                                }
                            ]
                        },
                        "h0",
                    ]
                ]
            },
        )

        headers = await provider.get_headers("msg-1")
        assert "List-Unsubscribe" not in headers
        assert headers["From"] == "sender@x.com"


# ---------------------------------------------------------------------------
# get_body()
# ---------------------------------------------------------------------------


class TestGetBody:
    async def test_returns_html_body(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "msg-1",
                                    "bodyValues": {
                                        "html1": {"value": "<p>Hello world</p>"},
                                        "text1": {"value": "Hello world"},
                                    },
                                    "htmlBody": [{"partId": "html1"}],
                                    "textBody": [{"partId": "text1"}],
                                }
                            ]
                        },
                        "b0",
                    ]
                ]
            },
        )

        body = await provider.get_body("msg-1")
        assert body == "<p>Hello world</p>"

    async def test_falls_back_to_text_body(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "msg-1",
                                    "bodyValues": {
                                        "text1": {"value": "Plain text content"},
                                    },
                                    "htmlBody": [],
                                    "textBody": [{"partId": "text1"}],
                                }
                            ]
                        },
                        "b0",
                    ]
                ]
            },
        )

        body = await provider.get_body("msg-1")
        assert body == "Plain text content"

    async def test_missing_message_returns_empty_string(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={"methodResponses": [["Email/get", {"list": []}, "b0"]]},
        )

        body = await provider.get_body("nonexistent")
        assert body == ""


# ---------------------------------------------------------------------------
# send_simple()
# ---------------------------------------------------------------------------


class TestSendSimple:
    async def test_creates_and_submits_email(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/set",
                        {
                            "created": {"draft1": {"id": "email-new-1"}},
                        },
                        "s0",
                    ],
                    [
                        "EmailSubmission/set",
                        {
                            "created": {"sub1": {"id": "sub-new-1"}},
                        },
                        "s1",
                    ],
                ]
            },
        )

        # Should not raise.
        await provider.send_simple(
            to="unsub@example.com",
            subject="Unsubscribe",
            body="unsubscribe",
        )

        # Verify the JMAP request was sent.
        api_requests = [r for r in httpx_mock.get_requests() if r.url == FAKE_API_URL]
        assert len(api_requests) == 1
        import json

        body = json.loads(api_requests[0].content)
        # First method call should be Email/set.
        assert body["methodCalls"][0][0] == "Email/set"
        # Second method call should be EmailSubmission/set.
        assert body["methodCalls"][1][0] == "EmailSubmission/set"

    async def test_send_simple_validates_via_super(self, provider):
        """Base class validation still applies."""
        with pytest.raises(ValueError, match="does not appear to be unsubscribe"):
            await provider.send_simple("a@b.com", "Hello", "Just a note")

    async def test_send_simple_rejects_long_body(self, provider):
        long_body = "unsubscribe " + "x" * 50
        with pytest.raises(ValueError, match="exceeds 50 characters"):
            await provider.send_simple("a@b.com", "unsub", long_body)

    async def test_draft_creation_failure_raises(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/set",
                        {
                            "notCreated": {
                                "draft1": {
                                    "type": "invalidProperties",
                                    "description": "Missing required field",
                                }
                            },
                        },
                        "s0",
                    ],
                    [
                        "EmailSubmission/set",
                        {"notCreated": {}},
                        "s1",
                    ],
                ]
            },
        )

        with pytest.raises(RuntimeError, match="Failed to create draft email"):
            await provider.send_simple(
                to="unsub@example.com",
                subject="Unsubscribe",
                body="unsubscribe",
            )

    async def test_submission_failure_raises(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(
            url=FAKE_API_URL,
            json={
                "methodResponses": [
                    [
                        "Email/set",
                        {"created": {"draft1": {"id": "email-1"}}},
                        "s0",
                    ],
                    [
                        "EmailSubmission/set",
                        {
                            "notCreated": {
                                "sub1": {
                                    "type": "forbidden",
                                    "description": "Not allowed",
                                }
                            },
                        },
                        "s1",
                    ],
                ]
            },
        )

        with pytest.raises(RuntimeError, match="Failed to submit email"):
            await provider.send_simple(
                to="unsub@example.com",
                subject="Unsubscribe",
                body="unsubscribe",
            )


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    async def test_api_call_failure_raises(self, httpx_mock, provider):
        """Non-2xx from the JMAP API endpoint raises."""
        _add_session_mock(httpx_mock)
        httpx_mock.add_response(url=FAKE_API_URL, status_code=500)

        with pytest.raises(httpx.HTTPStatusError):
            await provider.get_headers("msg-1")

    async def test_session_auth_failure(self, httpx_mock, provider):
        httpx_mock.add_response(
            url="https://api.fastmail.com/jmap/session",
            status_code=403,
        )
        with pytest.raises(httpx.HTTPStatusError):
            await provider.search(date(2026, 3, 1), date(2026, 3, 7))


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_raises_if_neither_token_nor_api_base(self):
        with pytest.raises(ValueError, match="Either token or api_base"):
            FastmailProvider()

    def test_token_mode(self):
        p = FastmailProvider(token="tok")
        assert p._proxy_mode is False

    def test_proxy_mode(self):
        p = FastmailProvider(api_base="http://proxy:8080/fastmail")
        assert p._proxy_mode is True

    def test_proxy_strips_trailing_slash(self):
        p = FastmailProvider(api_base="http://proxy:8080/fastmail/")
        assert p._api_base == "http://proxy:8080/fastmail"


# ---------------------------------------------------------------------------
# Proxy mode
# ---------------------------------------------------------------------------


class TestProxyMode:
    async def test_session_uses_proxy_url(self, httpx_mock, proxy_provider):
        _add_proxy_session_mock(httpx_mock)

        await proxy_provider._ensure_session()

        assert proxy_provider._account_id == FAKE_ACCOUNT_ID
        # apiUrl should be rewritten through the proxy
        assert proxy_provider._api_url == FAKE_PROXY_API_URL

    async def test_no_auth_header_in_proxy_mode(self, httpx_mock, proxy_provider):
        _add_proxy_session_mock(httpx_mock)

        await proxy_provider._ensure_session()

        req = httpx_mock.get_requests()[0]
        assert "Authorization" not in req.headers

    async def test_auth_header_in_direct_mode(self, httpx_mock, provider):
        _add_session_mock(httpx_mock)

        await provider._ensure_session()

        req = httpx_mock.get_requests()[0]
        assert req.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"

    async def test_proxy_search(self, httpx_mock, proxy_provider):
        """Full search through proxy mode works end-to-end."""
        _add_proxy_session_mock(httpx_mock)

        # Mailbox/get
        httpx_mock.add_response(url=FAKE_PROXY_API_URL, json=MAILBOX_RESPONSE)

        # Email/query + Email/get
        httpx_mock.add_response(
            url=FAKE_PROXY_API_URL,
            json={
                "methodResponses": [
                    ["Email/query", {"ids": ["msg-p1"]}, "q0"],
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "msg-p1",
                                    "from": [{"email": "proxy@example.com"}],
                                    "subject": "Via proxy",
                                    "receivedAt": "2026-03-01T10:00:00Z",
                                    "header:List-Unsubscribe": None,
                                },
                            ]
                        },
                        "g0",
                    ],
                ]
            },
        )

        results = await proxy_provider.search(
            after=date(2026, 3, 1), before=date(2026, 3, 7)
        )
        assert len(results) == 1
        assert results[0].sender == "proxy@example.com"

        # All requests should have gone to the proxy, none to Fastmail directly
        for req in httpx_mock.get_requests():
            assert "api.fastmail.com" not in str(req.url)

    async def test_rewrite_api_url_preserves_path(self, proxy_provider):
        """apiUrl paths other than /jmap/api are preserved."""
        rewritten = proxy_provider._rewrite_api_url(
            "https://api.fastmail.com/jmap/api"
        )
        assert rewritten == f"{FAKE_PROXY_BASE}/jmap/api"

    async def test_rewrite_api_url_noop_in_direct_mode(self, provider):
        result = provider._rewrite_api_url("https://api.fastmail.com/jmap/api")
        assert result == "https://api.fastmail.com/jmap/api"
