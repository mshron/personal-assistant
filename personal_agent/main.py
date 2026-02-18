"""Personal agent entrypoint. Wraps Nanobot with guardrails."""

import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def _build_agent():
    """Construct the Nanobot AgentLoop from our config."""
    from nanobot.config.loader import load_config, get_data_dir
    from nanobot.bus.queue import MessageBus
    from nanobot.agent.loop import AgentLoop
    from nanobot.providers.litellm_provider import LiteLLMProvider

    # Load our config (not ~/.nanobot/config.json)
    config_path = Path(__file__).parent.parent / "nanobot-config.json"
    config = load_config(config_path)

    # Tokenizer mode: API key is inside the sealed secret, routed through proxy.
    # Direct mode: API key from environment, direct HTTPS to Anthropic.
    tokenized_anthropic = os.environ.get("TOKENIZED_ANTHROPIC", "")

    if tokenized_anthropic:
        # Through Tokenizer: dummy key, http base URL, sealed secret in headers
        api_key = "via-tokenizer"
        api_base = "http://api.anthropic.com"
        extra_headers = {"Proxy-Tokenizer": tokenized_anthropic}
    else:
        # Direct mode (local dev without Docker)
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("Error: Set ANTHROPIC_API_KEY (direct) or TOKENIZED_ANTHROPIC (via Tokenizer).")
            sys.exit(1)
        api_base = None
        extra_headers = None

    provider = LiteLLMProvider(
        api_key=api_key,
        api_base=api_base,
        default_model=config.agents.defaults.model,
        extra_headers=extra_headers,
        provider_name="anthropic",
    )

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


async def run():
    from personal_agent.nanobot_hooks import apply_guardrails
    agent = _build_agent()
    apply_guardrails(agent)
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
