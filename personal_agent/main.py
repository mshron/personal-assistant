"""Personal agent entrypoint. Wraps Nanobot with guardrails."""

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


class _RetryProvider:
    """Wraps a LiteLLM provider with retry-on-rate-limit and inter-call delay."""

    def __init__(self, inner, delay: float = 2.0, max_retries: int = 5):
        self._inner = inner
        self._delay = delay
        self._max_retries = max_retries

    async def chat(self, *args, **kwargs):
        for attempt in range(self._max_retries + 1):
            result = await self._inner.chat(*args, **kwargs)
            if result.finish_reason == "error" and "rate_limit" in (result.content or ""):
                wait = self._delay * (2 ** attempt)
                print(f"[rate-limit] Waiting {wait:.0f}s before retry ({attempt + 1}/{self._max_retries})", flush=True)
                await asyncio.sleep(wait)
                continue
            # Add a small delay between all calls to stay under TPM limits
            await asyncio.sleep(self._delay)
            return result
        return result  # Return last error if all retries exhausted

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _build_agent():
    """Construct the Nanobot AgentLoop from our config."""
    from nanobot.config.loader import load_config
    from nanobot.bus.queue import MessageBus
    from nanobot.agent.loop import AgentLoop
    from nanobot.providers.litellm_provider import LiteLLMProvider

    # Load our config (not ~/.nanobot/config.json)
    config_path = Path(__file__).parent.parent / "nanobot-config.json"
    config = load_config(config_path)

    # Inject MCP server env vars that can't be set statically in JSON.
    # Nanobot's MCP subprocess only inherits a whitelist (HOME, PATH, etc.),
    # so secrets must be passed explicitly via the env dict.
    cred_proxy_base = os.environ.get("CRED_PROXY_BASE", "")
    if not cred_proxy_base:
        print("Error: CRED_PROXY_BASE is required.")
        sys.exit(1)

    # Brave Search MCP server — routes through credential proxy.
    if "brave" in config.tools.mcp_servers:
        config.tools.mcp_servers["brave"].env["BRAVE_API_BASE"] = (
            f"{cred_proxy_base.rstrip('/')}/brave"
        )

    # Email MCP server needs provider base URLs.
    if "email" in config.tools.mcp_servers:
        config.tools.mcp_servers["email"].env["FASTMAIL_API_BASE"] = (
            f"{cred_proxy_base.rstrip('/')}/fastmail"
        )
        config.tools.mcp_servers["email"].env["GMAIL_API_BASE"] = (
            f"{cred_proxy_base.rstrip('/')}/gmail"
        )

    use_local_llm = os.environ.get("USE_LOCAL_LLM", "").lower() in ("1", "true", "yes")
    if use_local_llm:
        model = os.environ.get("LOCAL_LLM_MODEL", "qwen3.6-35b-a3b-thinking")
        inner_provider = LiteLLMProvider(
            api_key="proxy",
            api_base=f"{cred_proxy_base.rstrip('/')}/local-llm/v1",
            default_model=f"openai/{model}",
            extra_headers=None,
            provider_name="openai",
        )
        config.agents.defaults.model = f"openai/{model}"
    else:
        inner_provider = LiteLLMProvider(
            api_key="proxy",
            api_base=f"{cred_proxy_base.rstrip('/')}/anthropic",
            default_model=config.agents.defaults.model,
            extra_headers=None,
            provider_name="anthropic",
        )
    provider = _RetryProvider(inner_provider, delay=2.0, max_retries=5)

    bus = MessageBus()
    agent = AgentLoop(
        bus=bus,
        provider=provider,
        workspace=config.workspace_path,
        model=config.agents.defaults.model,
        temperature=config.agents.defaults.temperature,
        max_tokens=config.agents.defaults.max_tokens,
        max_iterations=config.agents.defaults.max_tool_iterations,
        memory_window=config.agents.defaults.memory_window,
        restrict_to_workspace=config.tools.restrict_to_workspace,
        mcp_servers=config.tools.mcp_servers,
    )

    return agent


async def cli_loop(agent):
    """Interactive CLI loop for development/testing."""
    print("Personal Agent (CLI mode). Type 'quit' to exit.\n")
    while True:
        try:
            user_input = input("> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if user_input.strip().lower() in ("quit", "exit"):
            break
        if not user_input.strip():
            continue
        from personal_agent.logging.client import log_event
        await log_event("user_message", content=user_input)
        response = await agent.process_direct(user_input)
        await log_event("agent_response", content=response)
        print(f"\n{response}\n")


_AUTO_CONTINUE_SENTINEL = "I reached the maximum number of tool call iterations"
_AUTO_CONTINUE_MAX = 3
_AUTO_CONTINUE_PROMPT = (
    "Continue from where you left off. Use additional tool calls as needed."
)


async def _maybe_auto_continue(
    bus,
    msg,
    counts: dict[str, int],
    max_retries: int = _AUTO_CONTINUE_MAX,
) -> None:
    """Re-inject a synthetic 'continue' inbound when nanobot reports it hit
    max_tool_iterations. Resets the per-session counter on any normal reply
    so a long-running session can hit the limit again later."""
    from nanobot.bus.events import InboundMessage

    if msg.metadata.get("_progress"):
        return

    session_key = f"{msg.channel}:{msg.chat_id}"
    if not msg.content.startswith(_AUTO_CONTINUE_SENTINEL):
        counts.pop(session_key, None)
        return

    count = counts.get(session_key, 0)
    if count >= max_retries:
        print(
            f"[auto-continue] {session_key} exhausted after {max_retries} retries",
            flush=True,
        )
        # Don't reset; stay exhausted until a non-sentinel reply arrives,
        # otherwise a stale sentinel could re-arm the loop indefinitely.
        return

    counts[session_key] = count + 1
    print(
        f"[auto-continue] {session_key} {count + 1}/{max_retries}",
        flush=True,
    )
    await bus.publish_inbound(InboundMessage(
        channel=msg.channel,
        sender_id="__auto_continue__",
        chat_id=msg.chat_id,
        content=_AUTO_CONTINUE_PROMPT,
    ))


async def run_zulip(agent):
    """Run the agent in Zulip gateway mode."""
    from personal_agent.zulip_channel import ZulipChannel, ZulipConfig

    config = ZulipConfig.from_env()
    channel = ZulipChannel(config, agent.bus)

    continue_count: dict[str, int] = {}

    async def _consume_outbound():
        """Route outbound messages from the bus to the Zulip channel."""
        while True:
            msg = await agent.bus.consume_outbound()
            if msg.channel == "zulip":
                await channel.send(msg)
            await _maybe_auto_continue(agent.bus, msg, continue_count)

    await asyncio.gather(
        agent.run(),
        channel.start(),
        _consume_outbound(),
    )


async def run():
    from personal_agent.nanobot_hooks import apply_guardrails
    agent = _build_agent()
    apply_guardrails(agent)

    mode = os.environ.get("AGENT_MODE", "cli")

    if mode == "zulip":
        await run_zulip(agent)
    else:
        await cli_loop(agent)
        await agent.close_mcp()


def main():
    load_dotenv()
    # Suppress litellm/nanobot debug noise
    from loguru import logger
    logger.disable("nanobot")

    asyncio.run(run())


if __name__ == "__main__":
    main()
