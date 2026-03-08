"""Tests for the Gmail REST API provider."""

from __future__ import annotations

import base64
import re
from datetime import date

import httpx
import pytest

from personal_agent.email.gmail import GmailProvider

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

FAKE_PROXY_BASE = "http://polynumeral-cred-proxy.flycast:8080/gmail"
FAKE_MESSAGES_URL = f"{FAKE_PROXY_BASE}/gmail/v1/users/me/messages"
FAKE_SEND_URL = f"{FAKE_PROXY_BASE}/gmail/v1/users/me/messages/send"


def _msg_url(msg_id: str) -> str:
    return f"{FAKE_MESSAGES_URL}/{msg_id}"


def _msg_url_pattern(msg_id: str) -> re.Pattern:
    """Match a message URL with any query params."""
    return re.compile(re.escape(f"{FAKE_MESSAGES_URL}/{msg_id}"))


def _messages_url_pattern() -> re.Pattern:
    """Match the messages list URL with any query params."""
    return re.compile(re.escape(FAKE_MESSAGES_URL) + r"(\?|$)")


@pytest.fixture
def provider():
    return GmailProvider(api_base=FAKE_PROXY_BASE)


# ---------------------------------------------------------------------------
# search()
# ---------------------------------------------------------------------------


class TestSearch:
    async def test_search_with_date_filtering(self, httpx_mock, provider):
        # Step 1: list returns message stubs
        httpx_mock.add_response(
            url=_messages_url_pattern(),
            json={
                "messages": [
                    {"id": "msg-1", "threadId": "t1"},
                    {"id": "msg-2", "threadId": "t2"},
                ],
            },
        )

        # Step 2: individual message fetches
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "internalDate": "1709272800000",  # 2024-03-01 10:00 UTC
                "payload": {
                    "headers": [
                        {"name": "From", "value": "alice@example.com"},
                        {"name": "Subject", "value": "Newsletter"},
                        {"name": "Date", "value": "Fri, 1 Mar 2024 10:00:00 +0000"},
                        {"name": "List-Unsubscribe", "value": "<mailto:unsub@example.com>"},
                    ]
                },
            },
        )
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-2"),
            json={
                "id": "msg-2",
                "internalDate": "1709359200000",  # 2024-03-02 10:00 UTC
                "payload": {
                    "headers": [
                        {"name": "From", "value": "Bob <bob@example.com>"},
                        {"name": "Subject", "value": "Hello"},
                        {"name": "Date", "value": "Sat, 2 Mar 2024 10:00:00 +0000"},
                    ]
                },
            },
        )

        results = await provider.search(
            after=date(2024, 3, 1),
            before=date(2024, 3, 7),
            folder="Inbox",
        )

        assert len(results) == 2
        assert results[0].message_id == "msg-1"
        assert results[0].sender == "alice@example.com"
        assert results[0].subject == "Newsletter"
        assert results[0].has_list_unsubscribe is True
        assert results[1].message_id == "msg-2"
        assert results[1].sender == "bob@example.com"  # extracted from angle brackets
        assert results[1].has_list_unsubscribe is False

    async def test_search_no_messages_returns_empty(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=_messages_url_pattern(),
            json={},
        )

        results = await provider.search(
            after=date(2024, 3, 1),
            before=date(2024, 3, 7),
        )
        assert results == []

    async def test_search_sends_correct_query(self, httpx_mock, provider):
        """Verify the query includes date range and label."""
        httpx_mock.add_response(url=_messages_url_pattern(), json={})

        await provider.search(
            after=date(2024, 3, 1),
            before=date(2024, 3, 7),
            folder="Inbox",
        )

        req = httpx_mock.get_requests()[0]
        from urllib.parse import unquote
        url_str = unquote(str(req.url))
        assert "after:2024/03/01" in url_str
        assert "before:2024/03/07" in url_str
        assert "INBOX" in url_str


# ---------------------------------------------------------------------------
# get_headers()
# ---------------------------------------------------------------------------


class TestGetHeaders:
    async def test_returns_unsubscribe_headers(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "payload": {
                    "headers": [
                        {"name": "List-Unsubscribe", "value": " <mailto:unsub@example.com> "},
                        {"name": "List-Unsubscribe-Post", "value": " List-Unsubscribe=One-Click "},
                        {"name": "From", "value": " alice@example.com "},
                        {"name": "Subject", "value": " Newsletter "},
                    ]
                },
            },
        )

        headers = await provider.get_headers("msg-1")

        assert headers["List-Unsubscribe"] == "<mailto:unsub@example.com>"
        assert headers["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
        assert headers["From"] == "alice@example.com"
        assert headers["Subject"] == "Newsletter"

    async def test_missing_message_returns_empty(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=_msg_url_pattern("nonexistent"),
            json={"id": "nonexistent", "payload": {"headers": []}},
        )

        headers = await provider.get_headers("nonexistent")
        assert headers == {}

    async def test_partial_headers(self, httpx_mock, provider):
        """Only present headers are returned."""
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "payload": {
                    "headers": [
                        {"name": "From", "value": " sender@x.com "},
                        {"name": "Subject", "value": " Hi "},
                    ]
                },
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
        html_content = "<p>Hello world</p>"
        encoded = base64.urlsafe_b64encode(html_content.encode()).decode()

        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "payload": {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {
                            "mimeType": "text/plain",
                            "body": {
                                "data": base64.urlsafe_b64encode(b"Hello world").decode(),
                                "size": 11,
                            },
                        },
                        {
                            "mimeType": "text/html",
                            "body": {"data": encoded, "size": len(html_content)},
                        },
                    ],
                },
            },
        )

        body = await provider.get_body("msg-1")
        assert body == "<p>Hello world</p>"

    async def test_falls_back_to_text_body(self, httpx_mock, provider):
        text_content = "Plain text content"
        encoded = base64.urlsafe_b64encode(text_content.encode()).decode()

        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "payload": {
                    "mimeType": "text/plain",
                    "body": {"data": encoded, "size": len(text_content)},
                },
            },
        )

        body = await provider.get_body("msg-1")
        assert body == "Plain text content"

    async def test_empty_payload_returns_empty_string(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-1"),
            json={
                "id": "msg-1",
                "payload": {"mimeType": "multipart/mixed", "parts": []},
            },
        )

        body = await provider.get_body("msg-1")
        assert body == ""


# ---------------------------------------------------------------------------
# send_simple()
# ---------------------------------------------------------------------------


class TestSendSimple:
    async def test_sends_base64_encoded_message(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=FAKE_SEND_URL,
            json={"id": "sent-1", "threadId": "t1", "labelIds": ["SENT"]},
        )

        await provider.send_simple(
            to="unsub@example.com",
            subject="Unsubscribe",
            body="unsubscribe",
        )

        req = httpx_mock.get_requests()[0]
        import json

        body = json.loads(req.content)
        assert "raw" in body
        # Decode and verify the MIME message
        decoded = base64.urlsafe_b64decode(body["raw"]).decode()
        assert "unsub@example.com" in decoded
        assert "Unsubscribe" in decoded

    async def test_send_simple_validates_via_super(self, provider):
        """Base class validation still applies."""
        with pytest.raises(ValueError, match="does not appear to be unsubscribe"):
            await provider.send_simple("a@b.com", "Hello", "Just a note")

    async def test_send_simple_rejects_long_body(self, provider):
        long_body = "unsubscribe " + "x" * 50
        with pytest.raises(ValueError, match="exceeds 50 characters"):
            await provider.send_simple("a@b.com", "unsub", long_body)

    async def test_send_failure_raises(self, httpx_mock, provider):
        httpx_mock.add_response(
            url=FAKE_SEND_URL,
            status_code=403,
        )

        with pytest.raises(httpx.HTTPStatusError):
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
        """Non-2xx from the Gmail API endpoint raises."""
        httpx_mock.add_response(url=_msg_url_pattern("msg-1"), status_code=500)

        with pytest.raises(httpx.HTTPStatusError):
            await provider.get_headers("msg-1")

    async def test_search_api_failure_raises(self, httpx_mock, provider):
        httpx_mock.add_response(url=_messages_url_pattern(), status_code=401)

        with pytest.raises(httpx.HTTPStatusError):
            await provider.search(date(2024, 3, 1), date(2024, 3, 7))


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_raises_if_no_api_base(self):
        with pytest.raises(ValueError, match="api_base must be provided"):
            GmailProvider(api_base="")

    def test_strips_trailing_slash(self):
        p = GmailProvider(api_base="http://proxy:8080/gmail/")
        assert p._api_base == "http://proxy:8080/gmail"


# ---------------------------------------------------------------------------
# Proxy routing
# ---------------------------------------------------------------------------


class TestProxyRouting:
    async def test_no_auth_header_sent(self, httpx_mock, provider):
        """Provider should not send Authorization header -- proxy handles it."""
        httpx_mock.add_response(url=_messages_url_pattern(), json={})

        await provider.search(date(2024, 3, 1), date(2024, 3, 7))

        req = httpx_mock.get_requests()[0]
        assert "Authorization" not in req.headers

    async def test_all_requests_go_through_proxy(self, httpx_mock, provider):
        """All requests should go through the proxy base URL."""
        httpx_mock.add_response(
            url=_messages_url_pattern(),
            json={"messages": [{"id": "msg-p1", "threadId": "t1"}]},
        )
        httpx_mock.add_response(
            url=_msg_url_pattern("msg-p1"),
            json={
                "id": "msg-p1",
                "internalDate": "1709272800000",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "proxy@example.com"},
                        {"name": "Subject", "value": "Via proxy"},
                    ]
                },
            },
        )

        results = await provider.search(
            after=date(2024, 3, 1), before=date(2024, 3, 7)
        )
        assert len(results) == 1
        assert results[0].sender == "proxy@example.com"

        # All requests should have gone to the proxy, none to Google directly
        for req in httpx_mock.get_requests():
            assert "googleapis.com" not in str(req.url)


# ---------------------------------------------------------------------------
# Folder mapping
# ---------------------------------------------------------------------------


class TestFolderMapping:
    def test_maps_common_folders(self, provider):
        assert provider._resolve_label_id("Inbox") == "INBOX"
        assert provider._resolve_label_id("inbox") == "INBOX"
        assert provider._resolve_label_id("Sent") == "SENT"
        assert provider._resolve_label_id("Trash") == "TRASH"
        assert provider._resolve_label_id("Spam") == "SPAM"

    def test_passes_through_unknown_labels(self, provider):
        assert provider._resolve_label_id("Label_42") == "Label_42"


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------


class TestBodyExtraction:
    def test_simple_html(self):
        html = "<p>Hello</p>"
        payload = {
            "mimeType": "text/html",
            "body": {"data": base64.urlsafe_b64encode(html.encode()).decode(), "size": len(html)},
        }
        assert GmailProvider._extract_body(payload) == html

    def test_simple_plain_text(self):
        text = "Hello plain"
        payload = {
            "mimeType": "text/plain",
            "body": {"data": base64.urlsafe_b64encode(text.encode()).decode(), "size": len(text)},
        }
        assert GmailProvider._extract_body(payload) == text

    def test_multipart_prefers_html(self):
        html = "<b>Bold</b>"
        text = "Bold"
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(text.encode()).decode()},
                },
                {
                    "mimeType": "text/html",
                    "body": {"data": base64.urlsafe_b64encode(html.encode()).decode()},
                },
            ],
        }
        assert GmailProvider._extract_body(payload) == html

    def test_empty_parts(self):
        payload = {"mimeType": "multipart/mixed", "parts": []}
        assert GmailProvider._extract_body(payload) == ""
