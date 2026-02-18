# Guardrails-First Implementation — Design

Refines the [personal agent design](2026-02-17-personal-agent-design.md) with a guardrails-first implementation order: get Nanobot running with all three defense layers on Fly.io before adding Zulip.

## Decisions Made

- **Interface during development**: CLI channel (`nanobot agent`). Zulip added after guardrails are validated.
- **Guardrail integration**: Thin Python wrapper around Nanobot (Approach A). Nanobot stays unmodified. Our package hooks into the agent loop for PromptGuard scanning and Action Review.
- **Fly.io deployment**: Single 4GB Machine running all three processes (agent, tokenizer, log-service) via supervisord.
- **Git**: Init repo immediately, commit at each milestone. CI/CD for Fly deploy deferred.

## Project Structure

```
personal-agent/
├── docker-compose.yml          # All services: agent, tokenizer, log-service
├── Dockerfile                  # Agent container (Nanobot + our wrapper)
├── fly.toml                    # Fly.io deployment config
├── pyproject.toml              # Python deps: nanobot-ai, httpx, etc.
├── .env.example                # Template (exists)
├── nanobot-config.json         # Nanobot's config (model, tools, MCP servers)
├── src/
│   └── personal_agent/
│       ├── __init__.py
│       ├── main.py             # Entrypoint: wraps nanobot agent with our hooks
│       ├── nanobot_hooks.py    # ALL Nanobot-internal coupling isolated here
│       ├── guardrails/
│       │   ├── __init__.py
│       │   ├── promptguard.py  # Layer 1: scan content via Groq PromptGuard
│       │   └── action_review.py # Layer 2: Haiku alignment check
│       └── logging/
│           ├── __init__.py
│           └── client.py       # HTTP client for the log service
├── log-service/
│   ├── Dockerfile
│   └── main.py                 # ~50 lines, HTTP POST append-only logger
├── tokenizer/                  # Config and scripts for tokenizer setup
│   ├── generate-keypair.sh     # Generate Curve25519 keypair
│   └── encrypt-secret.py       # Encrypt a secret to tokenizer's public key
├── tests/
│   ├── test_promptguard.py
│   ├── test_action_review.py
│   └── test_log_service.py
└── docs/plans/
```

## Service Architecture

Three processes in one Docker Compose stack (one Fly Machine in production):

```
┌─────────────────────────────────────────────────────┐
│              Docker Compose Network                   │
│                                                       │
│  ┌──────────────────┐    ┌─────────────────┐         │
│  │  agent            │───▸│  tokenizer       │──▸ APIs │
│  │  (Nanobot +       │    │  (Go, port 8080) │        │
│  │   personal_agent) │    │  OPEN_KEY=...    │        │
│  │  port: none       │    └─────────────────┘        │
│  └────────┬──────────┘                                │
│           │                                           │
│           │ HTTP POST    ┌─────────────────┐         │
│           └─────────────▸│  log-service     │         │
│                          │  (Python, 8081)  │         │
│                          │  Volume: /data   │         │
│                          └─────────────────┘         │
└─────────────────────────────────────────────────────┘
```

- **Agent**: Python 3.12 slim, `nanobot-ai` + `personal_agent`. Entrypoint: `python -m personal_agent.main`. HTTP through Tokenizer for all credentialed requests.
- **Tokenizer**: `superfly/tokenizer` Go binary. Env: `OPEN_KEY`. Internal network only.
- **Log-service**: ~50 lines Python. POST `/log` appends JSON lines to `/data/agent.jsonl`. Internal network only.

## Guardrail Integration

All Nanobot-internal coupling lives in `nanobot_hooks.py`. The wrapper intercepts at two points:

### Layer 1: PromptGuard (input scanning)

- Scans inbound content (email bodies, web fetch results, external content) via Groq's PromptGuard 2 86M endpoint
- Groq API key routed through Tokenizer, bound to `api.groq.com`
- On detection: log, reject, notify user
- Fires before content enters the agent's context

### Layer 2: Action Review (pre-tool-call check)

- Fires only for side-effecting tools (`send_email`, `make_purchase`, `run_claude_code`)
- Sends original intent + proposed action to Claude Haiku (through Tokenizer)
- Checks: unexpected domains, wrong recipients, high amounts, data exfiltration patterns
- ~100-200ms per check
- On rejection: log, block, notify user

### Layer 3: Tokenizer host allowlists (network-level)

- Passive. Each encrypted secret bound to specific hosts.
- No code needed — this is a property of how secrets are encrypted.

## Managing Nanobot as a Fast-Moving Dependency

Nanobot is 17 days old, multiple commits/day. Strategy:

1. **Pin version hard**: `nanobot-ai==0.1.4` in pyproject.toml. No ranges.
2. **Minimize coupling**: All internal hooks in one file (`nanobot_hooks.py`).
3. **Prefer public APIs**: BaseChannel for Zulip, MCP config for tools.
4. **Contribute upstream**: PR hook points (`on_before_tool_call`, `on_message_received`) if they don't exist. Contribute `zulip.py` as a channel.
5. **Upgrade protocol**: Read changelog → run tests → check hooks → bump pin.
6. **Fallback**: Wrapper is ~200-300 lines. Rewritable in an afternoon if needed.

## Implementation Milestones

| # | Milestone | Outcome | Commit |
|---|-----------|---------|--------|
| 1 | Project scaffold | pyproject.toml, docker-compose.yml stubs, structure | `init: project scaffold` |
| 2 | Nanobot CLI locally | `nanobot agent` responds via CLI. Anthropic key in .env. | `feat: nanobot CLI agent working locally` |
| 3 | Log service | Standalone container, POST /log writes JSON lines. Tested. | `feat: append-only log service` |
| 4 | Tokenizer setup | Keypair generated, Anthropic key encrypted, agent through Tokenizer. | `feat: tokenizer credential proxy` |
| 5 | PromptGuard | Input scanning via Groq. Tested with injection payloads. | `feat: promptguard input scanning` |
| 6 | Action Review | Haiku alignment check on tool calls. Tested with misaligned actions. | `feat: action review pre-tool-call` |
| 7 | Wrapper integration | All guardrails wired into Nanobot. End-to-end test locally. | `feat: guardrail wrapper for nanobot` |
| 8 | Dockerize | All three services in Docker Compose, working locally. | `feat: docker compose stack` |
| 9 | Deploy to Fly.io | `fly deploy`, agent on Fly. Test via `fly ssh console`. | `feat: fly.io deployment` |
| 10 | Zulip channel | `zulip.py` implements BaseChannel. Agent on Zulip streams. Contribute upstream. | `feat: zulip channel` |
