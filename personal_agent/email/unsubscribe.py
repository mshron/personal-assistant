"""Unsubscribe logic -- tries multiple methods in priority order."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from personal_agent.email.provider import EmailProvider

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class UnsubscribeResult:
    """Outcome of an unsubscribe attempt."""

    success: bool
    method: str
    detail: str


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------

# Matches <...> entries in a List-Unsubscribe header value.
_ANGLE_BRACKET_RE = re.compile(r"<([^>]+)>")


def parse_list_unsubscribe(header: str) -> list[str]:
    """Extract URLs from a List-Unsubscribe header value.

    The header may contain multiple comma-separated entries enclosed in
    angle brackets, e.g. ``<mailto:unsub@x.com>, <https://x.com/unsub>``.
    """
    return _ANGLE_BRACKET_RE.findall(header)


# ---------------------------------------------------------------------------
# Body-link extraction
# ---------------------------------------------------------------------------

_UNSUB_LINK_RE = re.compile(
    r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>',
    re.IGNORECASE | re.DOTALL,
)


def find_unsubscribe_links(html: str) -> list[str]:
    """Return URLs from anchor tags where href or text contains 'unsubscribe'."""
    results: list[str] = []
    for href, text in _UNSUB_LINK_RE.findall(html):
        if "unsubscribe" in href.lower() or "unsubscribe" in text.lower():
            if href.startswith(("http://", "https://")):
                results.append(href)
    return results


# ---------------------------------------------------------------------------
# Unsubscriber
# ---------------------------------------------------------------------------

# Timeout for outbound HTTP requests (seconds).
_HTTP_TIMEOUT = 15.0


class Unsubscriber:
    """Attempts to unsubscribe from a mailing list using multiple methods."""

    def __init__(self, provider: EmailProvider) -> None:
        self.provider = provider

    async def unsubscribe(self, message_id: str) -> UnsubscribeResult:
        """Try to unsubscribe from the sender of *message_id*.

        Methods are attempted in order of preference:

        1. List-Unsubscribe-Post (RFC 8058) one-click
        2. List-Unsubscribe mailto:
        3. List-Unsubscribe https:
        4. Body link parsing
        """
        headers = await self.provider.get_headers(message_id)

        # Normalise header names to lowercase for reliable lookup.
        lower_headers = {k.lower(): v for k, v in headers.items()}

        unsub_header = lower_headers.get("list-unsubscribe", "")
        unsub_post_header = lower_headers.get("list-unsubscribe-post", "")
        urls = parse_list_unsubscribe(unsub_header) if unsub_header else []

        # Classify URLs from header.
        mailto_urls = [u for u in urls if u.startswith("mailto:")]
        https_urls = [u for u in urls if u.startswith("https://")]

        last_result: UnsubscribeResult | None = None

        # --- Method 1: List-Unsubscribe-Post (RFC 8058) ---
        if unsub_post_header and https_urls:
            last_result = await self._try_one_click(https_urls[0])
            if last_result.success:
                return last_result

        # --- Method 2: mailto ---
        if mailto_urls:
            last_result = await self._try_mailto(mailto_urls[0])
            if last_result.success:
                return last_result

        # --- Method 3: https URL (POST then GET) ---
        if https_urls:
            last_result = await self._try_https(https_urls[0])
            if last_result.success:
                return last_result

        # --- Method 4: Body link parsing ---
        last_result = await self._try_body_link(message_id)
        if last_result.success:
            return last_result

        return last_result

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    async def _try_one_click(self, url: str) -> UnsubscribeResult:
        """RFC 8058 one-click POST."""
        try:
            async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT, follow_redirects=True
                ) as client:
                resp = await client.post(
                    url,
                    data={"List-Unsubscribe": "One-Click"},
                )
            if resp.is_success:
                return UnsubscribeResult(
                    success=True,
                    method="one_click",
                    detail=f"POST {url} -> {resp.status_code}",
                )
            return UnsubscribeResult(
                success=False,
                method="one_click",
                detail=f"POST {url} -> {resp.status_code}",
            )
        except httpx.HTTPError as exc:
            return UnsubscribeResult(
                success=False,
                method="one_click",
                detail=f"POST {url} failed: {exc}",
            )

    async def _try_mailto(self, mailto_url: str) -> UnsubscribeResult:
        """Send an unsubscribe email via the provider."""
        # Parse "mailto:user@example.com" (ignore optional ?subject=... params).
        address = mailto_url.removeprefix("mailto:").split("?")[0]
        try:
            await self.provider.send_simple(
                to=address,
                subject="unsubscribe",
                body="unsubscribe",
            )
            return UnsubscribeResult(
                success=True,
                method="mailto",
                detail=f"Sent unsubscribe email to {address}",
            )
        except Exception as exc:
            return UnsubscribeResult(
                success=False,
                method="mailto",
                detail=f"Failed to send to {address}: {exc}",
            )

    async def _try_https(self, url: str) -> UnsubscribeResult:
        """POST to the URL; fall back to GET if POST fails."""
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, follow_redirects=True
            ) as client:
                resp = await client.post(url)
                if resp.is_success:
                    return UnsubscribeResult(
                        success=True,
                        method="https",
                        detail=f"POST {url} -> {resp.status_code}",
                    )
                # Fall back to GET.
                resp = await client.get(url)
                if resp.is_success:
                    return UnsubscribeResult(
                        success=True,
                        method="https",
                        detail=f"GET {url} -> {resp.status_code}",
                    )
            return UnsubscribeResult(
                success=False,
                method="https",
                detail=f"POST and GET {url} both failed ({resp.status_code})",
            )
        except httpx.HTTPError as exc:
            return UnsubscribeResult(
                success=False,
                method="https",
                detail=f"{url} failed: {exc}",
            )

    async def _try_body_link(self, message_id: str) -> UnsubscribeResult:
        """Scan the message body for unsubscribe links and GET the first one."""
        try:
            body = await self.provider.get_body(message_id)
        except Exception as exc:
            return UnsubscribeResult(
                success=False,
                method="body_link",
                detail=f"Failed to get body: {exc}",
            )

        links = find_unsubscribe_links(body)
        if not links:
            return UnsubscribeResult(
                success=False,
                method="body_link",
                detail="No unsubscribe links found in body",
            )

        url = links[0]
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, follow_redirects=True
            ) as client:
                resp = await client.get(url)
            if resp.is_success:
                return UnsubscribeResult(
                    success=True,
                    method="body_link",
                    detail=f"GET {url} -> {resp.status_code}",
                )
            return UnsubscribeResult(
                success=False,
                method="body_link",
                detail=f"GET {url} -> {resp.status_code}",
            )
        except httpx.HTTPError as exc:
            return UnsubscribeResult(
                success=False,
                method="body_link",
                detail=f"GET {url} failed: {exc}",
            )
