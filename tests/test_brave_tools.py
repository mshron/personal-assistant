"""Tests for personal_agent.brave.tools MCP server."""

from __future__ import annotations

import pytest

FAKE_PROXY_BASE = "http://credential-proxy:8080/brave"


@pytest.fixture(autouse=True)
def _reset_api_base():
    """Reset cached API base between tests."""
    from personal_agent.brave import tools
    tools._BRAVE_API_BASE = ""
    yield
    tools._BRAVE_API_BASE = ""


@pytest.fixture(autouse=True)
def _set_brave_env(monkeypatch):
    monkeypatch.setenv("BRAVE_API_BASE", FAKE_PROXY_BASE)


# ---------------------------------------------------------------------------
# web_search
# ---------------------------------------------------------------------------


class TestWebSearch:
    async def test_search_single_query(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(
            url=f"{FAKE_PROXY_BASE}/res/v1/web/search?q=python+tutorials&count=10",
            json={
                "web": {
                    "results": [
                        {
                            "title": "Python Tutorial",
                            "url": "https://python.org/tutorial",
                            "description": "Learn Python",
                        },
                    ],
                },
            },
        )

        result = await web_search(queries=["python tutorials"])

        assert "Python Tutorial" in result
        assert "https://python.org/tutorial" in result
        assert "Learn Python" in result

    async def test_search_multiple_queries(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(
            json={
                "web": {
                    "results": [
                        {"title": "Result A", "url": "https://a.com", "description": "A"},
                    ],
                },
            },
        )
        httpx_mock.add_response(
            json={
                "web": {
                    "results": [
                        {"title": "Result B", "url": "https://b.com", "description": "B"},
                    ],
                },
            },
        )

        result = await web_search(queries=["query1", "query2"])

        assert "Result A" in result
        assert "Result B" in result
        assert '"query1"' in result
        assert '"query2"' in result

    async def test_search_empty_queries(self):
        from personal_agent.brave.tools import web_search

        result = await web_search(queries=[])
        assert "no queries" in result.lower()

    async def test_search_numbering_continuous(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(
            json={
                "web": {
                    "results": [
                        {"title": "First", "url": "https://1.com", "description": "1"},
                        {"title": "Second", "url": "https://2.com", "description": "2"},
                    ],
                },
            },
        )
        httpx_mock.add_response(
            json={
                "web": {
                    "results": [
                        {"title": "Third", "url": "https://3.com", "description": "3"},
                    ],
                },
            },
        )

        result = await web_search(queries=["a", "b"])
        assert "1: First" in result
        assert "2: Second" in result
        assert "3: Third" in result

    async def test_search_no_auth_header(self, httpx_mock):
        """Proxy handles auth — no X-Subscription-Token header from client."""
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(json={"web": {"results": []}})

        await web_search(queries=["test"])

        req = httpx_mock.get_requests()[0]
        assert "x-subscription-token" not in req.headers

    async def test_search_count_capped_at_20(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(json={"web": {"results": []}})

        await web_search(queries=["test"], count=50)

        req = httpx_mock.get_requests()[0]
        assert "count=20" in str(req.url)

    async def test_search_empty_results(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(json={"web": {"results": []}})

        result = await web_search(queries=["obscure query"])
        assert '"obscure query"' in result


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    async def test_missing_brave_api_base_raises(self, monkeypatch):
        from personal_agent.brave import tools
        tools._BRAVE_API_BASE = ""
        monkeypatch.delenv("BRAVE_API_BASE", raising=False)

        with pytest.raises(RuntimeError, match="BRAVE_API_BASE"):
            from personal_agent.brave.tools import web_search
            await web_search(queries=["test"])

    async def test_api_base_cached(self, httpx_mock):
        from personal_agent.brave.tools import web_search

        httpx_mock.add_response(json={"web": {"results": []}})
        httpx_mock.add_response(json={"web": {"results": []}})

        await web_search(queries=["a"])
        await web_search(queries=["b"])

        for req in httpx_mock.get_requests():
            assert str(req.url).startswith(FAKE_PROXY_BASE)
