"""Tests for personal_agent.kagi.tools MCP server."""

from __future__ import annotations

from unittest.mock import patch

import pytest

FAKE_PROXY_BASE = "http://credential-proxy:8080/kagi"


@pytest.fixture(autouse=True)
def _reset_api_base():
    """Reset cached API base between tests."""
    from personal_agent.kagi import tools
    tools._KAGI_API_BASE = ""
    yield
    tools._KAGI_API_BASE = ""


@pytest.fixture(autouse=True)
def _set_kagi_env(monkeypatch):
    monkeypatch.setenv("KAGI_API_BASE", FAKE_PROXY_BASE)


# ---------------------------------------------------------------------------
# kagi_search
# ---------------------------------------------------------------------------


class TestKagiSearch:
    async def test_search_single_query(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_search

        httpx_mock.add_response(
            url=f"{FAKE_PROXY_BASE}/api/v0/search?q=python+tutorials&limit=10",
            json={
                "data": [
                    {
                        "t": 0,
                        "title": "Python Tutorial",
                        "url": "https://python.org/tutorial",
                        "snippet": "Learn Python",
                    },
                    {
                        "t": 1,
                        "list": ["related search"],
                    },
                ],
            },
        )

        result = await kagi_search(queries=["python tutorials"])

        assert "Python Tutorial" in result
        assert "https://python.org/tutorial" in result
        assert "Learn Python" in result
        # Related searches (t=1) should be filtered out
        assert "related search" not in result

    async def test_search_multiple_queries(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_search

        httpx_mock.add_response(
            json={
                "data": [
                    {"t": 0, "title": "Result A", "url": "https://a.com", "snippet": "A"},
                ],
            },
        )
        httpx_mock.add_response(
            json={
                "data": [
                    {"t": 0, "title": "Result B", "url": "https://b.com", "snippet": "B"},
                ],
            },
        )

        result = await kagi_search(queries=["query1", "query2"])

        assert "Result A" in result
        assert "Result B" in result
        assert '"query1"' in result
        assert '"query2"' in result

    async def test_search_empty_queries(self):
        from personal_agent.kagi.tools import kagi_search

        result = await kagi_search(queries=[])
        assert "no queries" in result.lower()

    async def test_search_api_error(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_search

        httpx_mock.add_response(
            json={"error": [{"code": 0, "msg": "Insufficient credits"}]},
        )

        result = await kagi_search(queries=["test"])
        assert "ERROR" in result

    async def test_search_numbering_continuous(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_search

        httpx_mock.add_response(
            json={
                "data": [
                    {"t": 0, "title": "First", "url": "https://1.com", "snippet": "1"},
                    {"t": 0, "title": "Second", "url": "https://2.com", "snippet": "2"},
                ],
            },
        )
        httpx_mock.add_response(
            json={
                "data": [
                    {"t": 0, "title": "Third", "url": "https://3.com", "snippet": "3"},
                ],
            },
        )

        result = await kagi_search(queries=["a", "b"])
        assert "1: First" in result
        assert "2: Second" in result
        assert "3: Third" in result

    async def test_search_no_auth_header(self, httpx_mock):
        """Proxy handles auth — no Authorization header from client."""
        from personal_agent.kagi.tools import kagi_search

        httpx_mock.add_response(json={"data": []})

        await kagi_search(queries=["test"])

        req = httpx_mock.get_requests()[0]
        assert "authorization" not in req.headers


# ---------------------------------------------------------------------------
# kagi_summarizer
# ---------------------------------------------------------------------------


class TestKagiSummarizer:
    async def test_summarize_url(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_summarizer

        httpx_mock.add_response(
            json={
                "data": {"output": "This article discusses Python best practices."},
            },
        )

        result = await kagi_summarizer(url="https://example.com/article")

        assert "Python best practices" in result

    async def test_summarize_with_options(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_summarizer
        import json

        httpx_mock.add_response(
            json={"data": {"output": "Key points:\n- Point 1\n- Point 2"}},
        )

        result = await kagi_summarizer(
            url="https://example.com",
            summary_type="takeaway",
            target_language="EN",
        )

        assert "Key points" in result
        req = httpx_mock.get_requests()[0]
        assert "summary_type=takeaway" in str(req.url)
        assert "target_language=EN" in str(req.url)

    async def test_summarize_empty_url(self):
        from personal_agent.kagi.tools import kagi_summarizer

        result = await kagi_summarizer(url="")
        assert "no url" in result.lower()

    async def test_summarize_api_error(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_summarizer

        httpx_mock.add_response(
            json={"error": [{"code": 0, "msg": "URL not accessible"}]},
        )

        result = await kagi_summarizer(url="https://example.com")
        assert "Error" in result


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    async def test_missing_kagi_api_base_raises(self, monkeypatch):
        from personal_agent.kagi import tools
        tools._KAGI_API_BASE = ""
        monkeypatch.delenv("KAGI_API_BASE", raising=False)

        with pytest.raises(RuntimeError, match="KAGI_API_BASE"):
            from personal_agent.kagi.tools import kagi_search
            await kagi_search(queries=["test"])

    async def test_api_base_cached(self, httpx_mock):
        from personal_agent.kagi.tools import kagi_search, _get_api_base

        httpx_mock.add_response(json={"data": []})
        httpx_mock.add_response(json={"data": []})

        await kagi_search(queries=["a"])
        await kagi_search(queries=["b"])

        # Both requests should use the same base
        for req in httpx_mock.get_requests():
            assert str(req.url).startswith(FAKE_PROXY_BASE)
