"""All Nanobot-internal coupling lives here.

Wraps ToolRegistry.execute to add:
- Pre-execution: Action Review for side-effecting tools
- Post-execution: PromptGuard scanning for external content tools
- Always: logging to the append-only log service
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


class GuardedToolRegistry:
    """Wraps a ToolRegistry to add guardrail checks around tool execution."""

    def __init__(self, inner, user_intent: str = ""):
        self._inner = inner
        self.user_intent = user_intent

    def __getattr__(self, name):
        """Proxy all attributes except execute to the inner registry."""
        return getattr(self._inner, name)

    async def execute(self, name: str, params: dict) -> str:
        # Pre-execution: Action Review
        if name in SIDE_EFFECTING_TOOLS:
            review = await review_action(self.user_intent, name, params)
            await log_event("action_review", tool=name, args=params,
                            approved=review.approved, reason=review.reason)
            if not review.approved:
                return f"Action blocked by safety review: {review.reason}"

        # Execute the tool
        result = await self._inner.execute(name, params)

        # Post-execution: PromptGuard scanning
        if name in EXTERNAL_CONTENT_TOOLS:
            scan = await scan_content(result)
            await log_event("promptguard_scan", tool=name,
                            is_malicious=scan.is_malicious)
            if scan.is_malicious:
                return (
                    "Content blocked: suspected prompt injection detected in "
                    f"output from {name}. The content has been logged for review."
                )

        # Log the tool call
        await log_event("tool_call", tool=name, args=params,
                        result_length=len(result))

        return result


def wrap_tool_registry(registry, user_intent: str = "") -> GuardedToolRegistry:
    """Create a guarded wrapper around a ToolRegistry."""
    return GuardedToolRegistry(registry, user_intent)


def apply_guardrails(agent) -> None:
    """Monkey-patch an AgentLoop to use guarded tool execution.

    Replaces agent.tools with a GuardedToolRegistry wrapper.
    The wrapper delegates all methods to the original registry but
    intercepts execute() to add guardrail checks.
    """
    agent.tools = GuardedToolRegistry(agent.tools)
