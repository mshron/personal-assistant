"""HTTP client for the append-only log service."""

import os

import httpx

LOG_SERVICE_URL = os.environ.get("LOG_SERVICE_URL", "http://localhost:8081/log")

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=5.0)
    return _client


async def log_event(event_type: str, **data) -> None:
    """Log an event to the append-only log service. Fire-and-forget."""
    try:
        await _get_client().post(
            LOG_SERVICE_URL,
            json={"event": event_type, **data},
        )
    except httpx.HTTPError:
        pass  # Don't crash the agent if logging fails
