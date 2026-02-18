"""All Nanobot-internal coupling lives here.

Wraps ToolRegistry.execute and LLMProvider.chat to add:
- Pre-execution: Action Review for side-effecting tools
- Post-execution: PromptGuard scanning for external content tools
- Full instrumentation: every LLM call, tool call, and result is logged
"""

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
})

# Truncate long values in logs to keep JSONL lines manageable
_MAX_LOG_LEN = 2000


def _truncate(s: str) -> str:
    if len(s) <= _MAX_LOG_LEN:
        return s
    return s[:_MAX_LOG_LEN] + f"... [truncated, {len(s)} chars total]"


class GuardedToolRegistry:
    """Wraps a ToolRegistry to add guardrail checks around tool execution."""

    def __init__(self, inner, user_intent: str = ""):
        self._inner = inner
        self.user_intent = user_intent

    def __getattr__(self, name):
        """Proxy all attributes except execute to the inner registry."""
        return getattr(self._inner, name)

    async def execute(self, name: str, params: dict) -> str:
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


class InstrumentedProvider:
    """Wraps an LLMProvider to log every LLM request and response."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def chat(self, messages, tools=None, model=None,
                   max_tokens=4096, temperature=0.7):
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

        return response


def wrap_tool_registry(registry, user_intent: str = "") -> GuardedToolRegistry:
    """Create a guarded wrapper around a ToolRegistry."""
    return GuardedToolRegistry(registry, user_intent)


def apply_guardrails(agent) -> None:
    """Monkey-patch an AgentLoop to use guarded tool execution and LLM logging.

    Replaces agent.tools with a GuardedToolRegistry wrapper and
    agent.provider with an InstrumentedProvider wrapper.
    """
    agent.tools = GuardedToolRegistry(agent.tools)
    agent.provider = InstrumentedProvider(agent.provider)
