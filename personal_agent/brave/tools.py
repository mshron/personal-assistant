"""Brave Search MCP tools -- FastMCP server exposing web search via credential proxy."""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("brave")

_BRAVE_API_BASE: str = ""


def _get_api_base() -> str:
    global _BRAVE_API_BASE
    if not _BRAVE_API_BASE:
        _BRAVE_API_BASE = os.environ.get("BRAVE_API_BASE", "")
        if not _BRAVE_API_BASE:
            raise RuntimeError(
                "BRAVE_API_BASE environment variable must be set "
                "(e.g. http://credential-proxy:8080/brave)"
            )
    return _BRAVE_API_BASE.rstrip("/")


@mcp.tool()
async def web_search(
    queries: list[str],
    count: int = 10,
) -> str:
    """Search the web using Brave Search.

    Parameters
    ----------
    queries:
        One or more search queries. Results from all queries are combined.
    count:
        Max results per query (default 10, max 20).
    """
    if not queries:
        return "Error: no queries provided."

    base = _get_api_base()
    results_parts: list[str] = []
    result_number = 1

    async with httpx.AsyncClient(timeout=15.0) as client:
        for query in queries:
            resp = await client.get(
                f"{base}/res/v1/web/search",
                params={"q": query, "count": min(count, 20)},
            )
            resp.raise_for_status()
            data = resp.json()

            web = data.get("web", {})
            search_results = web.get("results", [])
            lines: list[str] = [f'-----\nResults for search query "{query}":\n-----']

            for r in search_results:
                title = r.get("title", "N/A")
                url = r.get("url", "N/A")
                description = r.get("description", "N/A")
                lines.append(
                    f"{result_number}: {title}\n{url}\n{description}"
                )
                result_number += 1

            results_parts.append("\n\n".join(lines))

    return "\n\n".join(results_parts)


def main() -> None:
    """Run the brave MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
