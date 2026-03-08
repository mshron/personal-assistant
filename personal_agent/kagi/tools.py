"""Kagi MCP tools -- FastMCP server exposing search and summarize via credential proxy."""

from __future__ import annotations

import os
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kagi")

_KAGI_API_BASE: str = ""


def _get_api_base() -> str:
    global _KAGI_API_BASE
    if not _KAGI_API_BASE:
        _KAGI_API_BASE = os.environ.get("KAGI_API_BASE", "")
        if not _KAGI_API_BASE:
            raise RuntimeError(
                "KAGI_API_BASE environment variable must be set "
                "(e.g. http://credential-proxy:8080/kagi)"
            )
    return _KAGI_API_BASE.rstrip("/")


@mcp.tool()
async def kagi_search(
    queries: list[str],
    limit: int = 10,
) -> str:
    """Search the web using the Kagi Search API.

    Parameters
    ----------
    queries:
        One or more search queries. Results from all queries are combined.
    limit:
        Max results per query (default 10).
    """
    if not queries:
        return "Error: no queries provided."

    base = _get_api_base()
    results_parts: list[str] = []
    result_number = 1

    async with httpx.AsyncClient(timeout=15.0) as client:
        for query in queries:
            resp = await client.get(
                f"{base}/api/v0/search",
                params={"q": query, "limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()

            if error := data.get("error"):
                results_parts.append(f'Results for "{query}": ERROR: {error}')
                continue

            search_results = [r for r in data.get("data", []) if r.get("t") == 0]
            lines: list[str] = [f'-----\nResults for search query "{query}":\n-----']

            for r in search_results:
                title = r.get("title", "N/A")
                url = r.get("url", "N/A")
                published = r.get("published", "Not Available")
                snippet = r.get("snippet", "N/A")
                lines.append(
                    f"{result_number}: {title}\n{url}\n"
                    f"Published Date: {published}\n{snippet}"
                )
                result_number += 1

            results_parts.append("\n\n".join(lines))

    return "\n\n".join(results_parts)


@mcp.tool()
async def kagi_summarizer(
    url: str,
    summary_type: Literal["summary", "takeaway"] = "summary",
    target_language: str | None = None,
) -> str:
    """Summarize content from a URL using the Kagi Summarizer API.

    Can summarize any document type (text webpage, video, audio, etc.).

    Parameters
    ----------
    url:
        URL of the document to summarize.
    summary_type:
        "summary" for paragraph prose, "takeaway" for bulleted key points.
    target_language:
        Language code for output (e.g. "EN"). If omitted, uses document language.
    """
    if not url:
        return "Error: no URL provided."

    base = _get_api_base()
    params: dict[str, str] = {
        "url": url,
        "engine": os.environ.get("KAGI_SUMMARIZER_ENGINE", "cecil"),
        "summary_type": summary_type,
    }
    if target_language:
        params["target_language"] = target_language

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{base}/api/v0/summarize", params=params)
        resp.raise_for_status()
        data = resp.json()

    if error := data.get("error"):
        return f"Error: {error}"

    return data.get("data", {}).get("output", "No summary returned.")


def main() -> None:
    """Run the kagi MCP server over stdio."""
    import asyncio

    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
