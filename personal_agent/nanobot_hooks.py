"""All Nanobot-internal coupling lives here.

Wraps ToolRegistry.execute and LLMProvider.chat to add:
- Pre-execution: Action Review for side-effecting tools
- Post-execution: PromptGuard scanning for external content tools
- Full instrumentation: every LLM call, tool call, and result is logged
- Token-bucket rate limiting for Anthropic API calls
"""

import asyncio
import os
import sys
import time

from personal_agent.guardrails.action_review import (
    ReviewResult,
    review_action,
    SIDE_EFFECTING_TOOLS,
)
from personal_agent.guardrails.promptguard import ScanResult, scan_content
from personal_agent.logging.client import log_event

# Tools whose output comes from external sources and needs PromptGuard scanning
EXTERNAL_CONTENT_TOOLS = frozenset({
    "web_fetch",
    "web_search",
    "read_email",
    # MCP-namespaced versions
    "mcp_web_web_fetch",
    "mcp_web_web_search",
    "mcp_email_read_email",
    "mcp_kagi_search",
    "mcp_kagi_summarizer",
})

# Truncate long values in logs to keep JSONL lines manageable
_MAX_LOG_LEN = 2000


def _truncate(s: str) -> str:
    if len(s) <= _MAX_LOG_LEN:
        return s
    return s[:_MAX_LOG_LEN] + f"... [truncated, {len(s)} chars total]"


def _extract_intent(content: str) -> str:
    """Extract user intent from a message for action review.

    The actual user request is typically at the end of the content
    (channels may prepend conversation history). Take the last 500
    chars to keep the review prompt focused and model-friendly.
    """
    return content.strip()[-500:]


class GuardedToolRegistry:
    """Wraps a ToolRegistry to add guardrail checks around tool execution."""

    def __init__(self, inner, user_intent: str = ""):
        self._inner = inner
        self.user_intent = user_intent

    def __getattr__(self, name):
        """Proxy all attributes except execute to the inner registry."""
        return getattr(self._inner, name)

    async def execute(self, name: str, params: dict) -> str:
        try:
            return await self._execute_guarded(name, params)
        except Exception as exc:
            # Last-resort catch so a guardrail bug never kills the agent loop
            print(f"[guardrails] unhandled error in execute({name}): "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            await log_event("guardrail_error", tool=name,
                            error=f"{type(exc).__name__}: {exc}")
            return await self._inner.execute(name, params)

    async def _execute_guarded(self, name: str, params: dict) -> str:
        await log_event("tool_call", tool=name, args=params)

        # Pre-execution: Action Review
        if name in SIDE_EFFECTING_TOOLS:
            review = await review_action(self.user_intent, name, params)
            await log_event("action_review", tool=name,
                            approved=review.approved, reason=review.reason)
            if not review.approved:
                blocked_msg = f"Action blocked by safety review: {review.reason}"
                await log_event("tool_result", tool=name, blocked=True,
                                reason=review.reason)
                return blocked_msg

        # Execute the tool
        result = await self._inner.execute(name, params)

        await log_event("tool_result", tool=name,
                        result=_truncate(result), result_length=len(result))

        # Post-execution: PromptGuard scanning
        if name in EXTERNAL_CONTENT_TOOLS:
            scan = await scan_content(result)
            await log_event("promptguard_scan", tool=name,
                            is_malicious=scan.is_malicious,
                            scores=scan.chunk_scores)
            if scan.is_malicious:
                blocked_msg = (
                    "Content blocked: suspected prompt injection detected in "
                    f"output from {name}. The content has been logged for review."
                )
                await log_event("promptguard_blocked", tool=name,
                                content=_truncate(result))
                return blocked_msg

        return result


class TokenBucket:
    """Token-bucket rate limiter for API calls.

    Starts full at `tokens_per_minute` tokens. Refills at TPM/60 tokens per
    second. The bucket can go negative after consume(); wait() sleeps until it
    refills back to zero.
    """

    def __init__(self, tokens_per_minute: int):
        self.rate = tokens_per_minute / 60.0  # tokens/sec
        self.capacity = float(tokens_per_minute)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.rate)
        self.last_refill = now

    async def wait(self):
        self._refill()
        if self.tokens <= 0:
            wait_secs = -self.tokens / self.rate
            await asyncio.sleep(wait_secs)
            self._refill()

    def consume(self, count: int):
        self.tokens -= count


class InstrumentedProvider:
    """Wraps an LLMProvider to log every LLM request and response."""

    def __init__(self, inner, bucket: TokenBucket | None = None,
                 guarded_tools: GuardedToolRegistry | None = None):
        self._inner = inner
        self._bucket = bucket
        self._guarded_tools = guarded_tools

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def chat(self, messages, tools=None, model=None,
                   max_tokens=4096, temperature=0.7):
        # Update user intent for action review from the latest user message
        if self._guarded_tools and messages:
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str) and content.strip():
                        self._guarded_tools.user_intent = _extract_intent(content)
                        break

        # Rate-limit: wait if bucket is depleted
        if self._bucket:
            await self._bucket.wait()

        # Log the request (last message is the most relevant)
        last_msg = messages[-1] if messages else {}
        await log_event("llm_request",
                        model=model or "default",
                        message_count=len(messages),
                        last_role=last_msg.get("role"),
                        last_content=_truncate(str(last_msg.get("content", ""))),
                        tool_count=len(tools) if tools else 0)

        response = await self._inner.chat(
            messages, tools=tools, model=model,
            max_tokens=max_tokens, temperature=temperature,
        )

        # Log the response
        tool_calls = [{"name": tc.name, "args": tc.arguments}
                      for tc in response.tool_calls] if response.tool_calls else []
        await log_event("llm_response",
                        content=_truncate(response.content or ""),
                        tool_calls=tool_calls,
                        finish_reason=response.finish_reason,
                        usage=response.usage)

        # Rate-limit: consume actual tokens used
        if self._bucket and response.usage:
            total = response.usage.get("prompt_tokens", 0) + response.usage.get("completion_tokens", 0)
            self._bucket.consume(total)

        return response


def wrap_tool_registry(registry, user_intent: str = "") -> GuardedToolRegistry:
    """Create a guarded wrapper around a ToolRegistry."""
    return GuardedToolRegistry(registry, user_intent)


def apply_guardrails(agent) -> None:
    """Monkey-patch an AgentLoop to use guarded tool execution and LLM logging.

    Replaces agent.tools with a GuardedToolRegistry wrapper and
    agent.provider with an InstrumentedProvider wrapper.
    Rate-limits LLM calls if RATE_LIMIT_TPM is set to a positive integer.
    """
    tpm = int(os.environ.get("RATE_LIMIT_TPM", "0"))
    bucket = TokenBucket(tpm) if tpm > 0 else None

    guarded_tools = GuardedToolRegistry(agent.tools)
    agent.tools = guarded_tools
    agent.provider = InstrumentedProvider(agent.provider, bucket=bucket,
                                         guarded_tools=guarded_tools)
