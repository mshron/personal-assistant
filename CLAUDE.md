# Personal Agent

Nanobot-based personal assistant deployed to Fly.io, communicating via Zulip.

## Quick reference

```bash
uv run pytest                    # run all tests
uv run pytest tests/test_zulip_channel.py  # run specific test file
fly deploy                       # deploy to Fly.io
fly logs -a polynumeral-assistant --no-tail  # check logs
fly ssh console -a polynumeral-assistant     # SSH into container
```

## Architecture

```
personal_agent/
  main.py              # entrypoint — builds nanobot AgentLoop, runs CLI or Zulip mode
  zulip_channel.py     # ZulipChannel(BaseChannel) — message routing, engaged topics
  nanobot_hooks.py     # wires guardrails into nanobot's tool execution
  guardrails/
    promptguard.py     # Layer 1: Groq-hosted LlamaGuard prompt injection detection
    action_review.py   # Layer 2: Groq-hosted action review before tool execution
  logging/
    client.py          # async log client → log-service sidecar
```

This project is a wrapper around [nanobot-ai](https://github.com/HKUDS/nanobot) — we do not modify nanobot's source code. Nanobot is a pinned dependency (`nanobot-ai==0.1.4`) that handles sessions, memory, tool execution, and LLM calls. All customization happens through nanobot's public interfaces: `BaseChannel` subclasses, `MessageBus` subscriptions, `AgentLoop` configuration, and provider wrappers. This keeps us able to upgrade nanobot as it evolves.

## Running locally

```bash
uv sync --dev              # install deps
cp .env.example .env       # fill in credentials
uv run python -m personal_agent.main   # CLI mode (default)
AGENT_MODE=zulip uv run python -m personal_agent.main  # Zulip mode
```

## Tests

```bash
uv run pytest              # all tests
uv run pytest -v           # verbose
uv run pytest -k "zulip"   # filter by name
```

All tests use `pytest-asyncio` with `asyncio_mode = "auto"`. Zulip channel tests mock the Zulip SDK client.

## Deployment

App: `polynumeral-assistant` on Fly.io (region: `iad`)

```bash
fly deploy                           # build + deploy
fly logs -a polynumeral-assistant --no-tail   # check startup
fly ssh console -a polynumeral-assistant      # debug
```

The container runs `start.sh` which starts the log-service sidecar and then the agent. Persistent data lives on a 1GB volume mounted at `/data`:
- `/data/nanobot/` — JSONL sessions, MEMORY.md, HISTORY.md
- `/data/logs/` — append-only audit log
- `/data/zulip_engaged_topics.json` — tracks which topics the bot is monitoring

### Secrets

**NEVER read, open, grep, or cat the `.env` file.** It contains live secrets and must only be edited by the user directly. Set production secrets via `fly secrets set`. Key secrets:
- `ANTHROPIC_API_KEY` — direct API key (no tokenizer)
- `ZULIP_SITE`, `ZULIP_EMAIL`, `ZULIP_API_KEY` — bot credentials
- `ZULIP_STREAMS` — comma-separated streams for non-mention monitoring
- `GROQ_API_KEY` — for PromptGuard (LlamaGuard) and Action Review (Safeguard 20B)
- `KAGI_API_KEY` — for Kagi search/summarizer MCP tools

## Zulip channel behavior

- Bot subscribes to configured streams and uses `all_public_streams=True` for full message delivery
- **@mentions work in any stream** — engages the topic for future monitoring
- **Engaged topics**: once @mentioned in a topic, the bot responds to all subsequent messages without requiring @mention
- **Topic history**: on first message in a topic each session, fetches prior messages via Zulip API and prepends as context
- **Engaged topics persist** across restarts via `/data/zulip_engaged_topics.json`
- `ZULIP_STREAMS` controls which streams get non-@mention monitoring; @mentions bypass this filter

## Key env vars

| Variable | Purpose |
|----------|---------|
| `AGENT_MODE` | `cli` (default) or `zulip` |
| `ANTHROPIC_API_KEY` | LLM API key |
| `ZULIP_SITE` | e.g. `https://polynumeral.zulipchat.com` |
| `ZULIP_EMAIL` | Bot email |
| `ZULIP_API_KEY` | Bot API key |
| `ZULIP_STREAMS` | Streams to monitor (comma-separated) |
| `ZULIP_ALLOW_FROM` | Optional sender ID allowlist |
| `GROQ_API_KEY` | For PromptGuard + Action Review (both layers) |
| `ACTION_REVIEW_MODEL` | Groq model for action review (default: `openai/gpt-oss-safeguard-20b`) |
| `KAGI_API_KEY` | For Kagi search/summarizer (MCP) |
| `RATE_LIMIT_TPM` | Token-bucket rate limit (tokens/min); 0 = off |
| `LOG_FILE` | Path for audit log JSONL |
| `LOG_SERVICE_URL` | URL of log-service sidecar |

## Debugging

### Fly.io logs (stdout/stderr)

```bash
fly logs -a polynumeral-assistant --no-tail   # recent logs
fly logs -a polynumeral-assistant              # stream live
```

Shows Zulip message receipt, startup, deploy errors, and `[guardrails]` stderr from `GuardedToolRegistry`. Does NOT show LLM calls or tool execution details.

### Sidecar audit logs (detailed)

The log-service sidecar writes structured JSONL to `/data/logs/agent.jsonl` on the persistent volume. This is the primary debugging tool — it records every LLM request/response, tool call/result, action review decision, and PromptGuard scan with timestamps.

```bash
fly ssh console -a polynumeral-assistant -C "tail -30 /data/logs/agent.jsonl"
```

Key event types: `llm_request`, `llm_response`, `tool_call`, `tool_result`, `action_review`, `promptguard_scan`, `promptguard_blocked`, `guardrail_error`.

### Debugging checklist

If the bot receives a message (shown in fly logs) but doesn't respond:
1. Check sidecar logs for an `llm_request` — if absent, the message never reached the agent loop (nanobot routing issue, not guardrails)
2. Check for `llm_response` with `finish_reason: "error"` — rate limit or API failure
3. Check for `action_review` with `approved: false` — guardrail blocked the tool call
4. Check for `guardrail_error` — unhandled exception in guardrails (fails open, logged to stderr)

## Git push

The GitHub SSH key lives in 1Password. If the user has stepped away and `git push` fails with "Permission denied (publickey)", don't troubleshoot — just note that the push is pending and move on. The user will unlock 1Password and push when they return.

## Dependencies

Managed with `uv`. Key deps: `nanobot-ai`, `zulip`, `httpx`, `pynacl`. Dev deps: `pytest`, `pytest-asyncio`, `pytest-httpx`.
