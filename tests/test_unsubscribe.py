"""Tests for the unsubscribe logic."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from personal_agent.email.provider import EmailProvider
from personal_agent.email.unsubscribe import (
    UnsubscribeResult,
    Unsubscriber,
    find_unsubscribe_links,
    parse_list_unsubscribe,
)


# ---------------------------------------------------------------------------
# Mock provider
# ---------------------------------------------------------------------------


class _MockProvider(EmailProvider):
    """In-memory provider for testing."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> None:
        self._headers = headers or {}
        self._body = body
        self.sent: list[dict[str, str]] = []

    async def search(self, after, before, folder="Inbox"):
        return []

    async def get_headers(self, message_id: str) -> dict[str, str]:
        return dict(self._headers)

    async def get_body(self, message_id: str) -> str:
        return self._body

    async def send_simple(self, to: str, subject: str, body: str) -> None:
        await super().send_simple(to, subject, body)
        self.sent.append({"to": to, "subject": subject, "body": body})


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


class TestParseListUnsubscribe:
    def test_single_mailto(self):
        assert parse_list_unsubscribe("<mailto:unsub@example.com>") == [
            "mailto:unsub@example.com"
        ]

    def test_single_https(self):
        assert parse_list_unsubscribe("<https://example.com/unsub>") == [
            "https://example.com/unsub"
        ]

    def test_multiple_urls(self):
        header = "<mailto:unsub@example.com>, <https://example.com/unsub>"
        urls = parse_list_unsubscribe(header)
        assert urls == ["mailto:unsub@example.com", "https://example.com/unsub"]

    def test_empty_string(self):
        assert parse_list_unsubscribe("") == []

    def test_no_angle_brackets(self):
        assert parse_list_unsubscribe("https://example.com/unsub") == []

    def test_multiple_https(self):
        header = "<https://a.com/unsub>, <https://b.com/unsub>"
        urls = parse_list_unsubscribe(header)
        assert len(urls) == 2

    def test_with_query_params(self):
        header = "<https://example.com/unsub?id=123&token=abc>"
        assert parse_list_unsubscribe(header) == [
            "https://example.com/unsub?id=123&token=abc"
        ]


# ---------------------------------------------------------------------------
# Body link extraction
# ---------------------------------------------------------------------------


class TestFindUnsubscribeLinks:
    def test_href_contains_unsubscribe(self):
        html = '<a href="https://example.com/unsubscribe?id=1">Click here</a>'
        assert find_unsubscribe_links(html) == [
            "https://example.com/unsubscribe?id=1"
        ]

    def test_text_contains_unsubscribe(self):
        html = '<a href="https://example.com/optout">Unsubscribe</a>'
        assert find_unsubscribe_links(html) == ["https://example.com/optout"]

    def test_case_insensitive(self):
        html = '<a href="https://example.com/UNSUBSCRIBE">click</a>'
        assert len(find_unsubscribe_links(html)) == 1

    def test_no_matches(self):
        html = '<a href="https://example.com/about">About us</a>'
        assert find_unsubscribe_links(html) == []

    def test_ignores_non_http_links(self):
        html = '<a href="mailto:unsub@example.com">Unsubscribe</a>'
        assert find_unsubscribe_links(html) == []

    def test_multiple_links(self):
        html = """
        <a href="https://a.com/unsubscribe">unsub</a>
        <a href="https://b.com/unsubscribe">unsub</a>
        """
        assert len(find_unsubscribe_links(html)) == 2

    def test_mixed_links(self):
        html = """
        <a href="https://example.com/home">Home</a>
        <a href="https://example.com/unsubscribe">Unsubscribe</a>
        <a href="https://example.com/about">About</a>
        """
        links = find_unsubscribe_links(html)
        assert links == ["https://example.com/unsubscribe"]


# ---------------------------------------------------------------------------
# Method 1: One-click (RFC 8058)
# ---------------------------------------------------------------------------


class TestOneClick:
    async def test_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://example.com/unsub", status_code=200)
        provider = _MockProvider(
            headers={
                "List-Unsubscribe": "<https://example.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            }
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "one_click"

    async def test_failure_falls_through(self, httpx_mock: HTTPXMock):
        """If one-click POST returns 500, should fall through to https method."""
        # First POST consumed by one-click attempt.
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="POST"
        )
        # Second POST consumed by https method attempt.
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="POST"
        )
        # GET fallback in https method succeeds.
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=200, method="GET"
        )
        provider = _MockProvider(
            headers={
                "List-Unsubscribe": "<https://example.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            }
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        # Falls through one_click -> https (GET fallback).
        assert result.method == "https"


# ---------------------------------------------------------------------------
# Method 2: mailto
# ---------------------------------------------------------------------------


class TestMailto:
    async def test_success(self):
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<mailto:unsub@example.com>"}
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "mailto"
        assert len(provider.sent) == 1
        assert provider.sent[0]["to"] == "unsub@example.com"

    async def test_mailto_with_query_params(self):
        provider = _MockProvider(
            headers={
                "List-Unsubscribe": "<mailto:unsub@example.com?subject=leave>"
            }
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "mailto"
        assert provider.sent[0]["to"] == "unsub@example.com"


# ---------------------------------------------------------------------------
# Method 3: https URL
# ---------------------------------------------------------------------------


class TestHttps:
    async def test_post_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://example.com/unsub", status_code=200)
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<https://example.com/unsub>"}
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "https"
        assert "POST" in result.detail

    async def test_post_fails_get_succeeds(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=405, method="POST"
        )
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=200, method="GET"
        )
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<https://example.com/unsub>"}
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "https"
        assert "GET" in result.detail

    async def test_both_fail(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="POST"
        )
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="GET"
        )
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<https://example.com/unsub>"},
            body="<p>No unsub link here</p>",
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is False


# ---------------------------------------------------------------------------
# Method 4: Body link
# ---------------------------------------------------------------------------


class TestBodyLink:
    async def test_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://example.com/unsubscribe?id=1", status_code=200
        )
        provider = _MockProvider(
            body='<a href="https://example.com/unsubscribe?id=1">Unsubscribe</a>'
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "body_link"

    async def test_no_links_in_body(self):
        provider = _MockProvider(body="<p>Just a normal email</p>")
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is False
        assert result.method == "body_link"
        assert "No unsubscribe links" in result.detail

    async def test_link_returns_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="https://example.com/unsubscribe", status_code=500
        )
        provider = _MockProvider(
            body='<a href="https://example.com/unsubscribe">Unsubscribe</a>'
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is False
        assert result.method == "body_link"


# ---------------------------------------------------------------------------
# Fallback chain
# ---------------------------------------------------------------------------


class TestFallbackChain:
    async def test_one_click_skipped_without_post_header(self, httpx_mock: HTTPXMock):
        """Without List-Unsubscribe-Post, should skip one-click and use https."""
        httpx_mock.add_response(url="https://example.com/unsub", status_code=200)
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<https://example.com/unsub>"}
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "https"

    async def test_mailto_preferred_over_body(self):
        """mailto should be tried before body link parsing."""
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<mailto:unsub@example.com>"},
            body='<a href="https://example.com/unsubscribe">Unsubscribe</a>',
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "mailto"

    async def test_all_methods_exhausted(self):
        provider = _MockProvider(body="<p>Nothing useful here</p>")
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is False
        assert result.method == "body_link"
        assert "No unsubscribe links" in result.detail

    async def test_mailto_then_https_order(self, httpx_mock: HTTPXMock):
        """With both mailto and https in header, mailto is tried first."""
        provider = _MockProvider(
            headers={
                "List-Unsubscribe": "<mailto:unsub@example.com>, <https://example.com/unsub>"
            }
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "mailto"

    async def test_https_fallback_to_body(self, httpx_mock: HTTPXMock):
        """If https method fails, falls through to body link."""
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="POST"
        )
        httpx_mock.add_response(
            url="https://example.com/unsub", status_code=500, method="GET"
        )
        httpx_mock.add_response(
            url="https://example.com/unsubscribe", status_code=200
        )
        provider = _MockProvider(
            headers={"List-Unsubscribe": "<https://example.com/unsub>"},
            body='<a href="https://example.com/unsubscribe">Unsubscribe</a>',
        )
        unsub = Unsubscriber(provider)
        result = await unsub.unsubscribe("msg1")
        assert result.success is True
        assert result.method == "body_link"


# ---------------------------------------------------------------------------
# UnsubscribeResult dataclass
# ---------------------------------------------------------------------------


class TestUnsubscribeResult:
    def test_fields(self):
        r = UnsubscribeResult(success=True, method="one_click", detail="OK")
        assert r.success is True
        assert r.method == "one_click"
        assert r.detail == "OK"
