"""Layer 1: Input scanning via Groq PromptGuard 2 86M.

Scans external content (email bodies, web pages, MCP tool results) for
prompt injection before it enters the agent's context.

PromptGuard has a 512-token context window. Long content is chunked and
scanned in parallel. If ANY chunk is flagged MALICIOUS, the whole content
is flagged.

Fails open: if Groq is unreachable, logs the error and returns benign.
Layer 2 (Action Review) is the backstop for harmful actions.
"""

import asyncio
import os
from dataclasses import dataclass

import httpx

GROQ_URL = os.environ.get(
    "GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions"
)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
PROMPTGUARD_MODEL = os.environ.get(
    "PROMPTGUARD_MODEL", "meta-llama/llama-prompt-guard-2-86m"
)
# Score above this threshold is considered a prompt injection attempt.
MALICIOUS_THRESHOLD = float(os.environ.get("PROMPTGUARD_THRESHOLD", "0.25"))
# Rough chars-per-chunk. 512 tokens ~ 1500 chars for English text.
CHUNK_SIZE = 1200

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        headers = {}
        if GROQ_API_KEY:
            headers["Authorization"] = f"Bearer {GROQ_API_KEY}"
        _client = httpx.AsyncClient(timeout=10.0, headers=headers)
    return _client


@dataclass
class ScanResult:
    is_malicious: bool
    is_benign: bool
    skipped: bool = False
    chunk_scores: list[float] | None = None


async def _scan_chunk(chunk: str) -> float:
    """Scan a single chunk. Returns injection probability (0.0–1.0)."""
    response = await _get_client().post(
        GROQ_URL,
        json={
            "model": PROMPTGUARD_MODEL,
            "messages": [{"role": "user", "content": chunk}],
        },
    )
    response.raise_for_status()
    raw = response.json()["choices"][0]["message"]["content"].strip()
    return float(raw)


async def scan_content(content: str) -> ScanResult:
    """Scan content for prompt injection. Returns ScanResult."""
    if not content.strip():
        return ScanResult(is_malicious=False, is_benign=True, skipped=True)

    chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]

    try:
        scores = await asyncio.gather(*[_scan_chunk(c) for c in chunks])
    except (httpx.HTTPError, httpx.StreamError, ValueError):
        # Groq unreachable or unparseable — fail open, Layer 2 is the backstop
        return ScanResult(is_malicious=False, is_benign=True, skipped=True)

    is_malicious = any(s >= MALICIOUS_THRESHOLD for s in scores)
    return ScanResult(
        is_malicious=is_malicious,
        is_benign=not is_malicious,
        chunk_scores=list(scores),
    )
