# Personal Agent

A personal assistant that communicates via [Zulip](https://zulip.com), built on [nanobot-ai](https://github.com/HKUDS/nanobot). It can read and send email (Fastmail), search the web (Brave), and run tools — all behind a two-layer guardrail system and a credential-isolating proxy.

## How it works

The agent runs as three containers:

```
┌──────────────────────────────────────────────────────┐
│                  Fly.io (private network)             │
│                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────┐ │
│  │   Agent      │──▸│  Credential  │──▸│ External  │ │
│  │ (no secrets) │   │    Proxy     │   │   APIs    │ │
│  │              │   │  (Caddy)     │   │           │ │
│  └──────┬───────┘   └──────────────┘   └───────────┘ │
│         │                                             │
│         ▼                                             │
│  ┌─────────────┐                                      │
│  │ Log Service  │  append-only audit log              │
│  │ (no secrets) │  (POST only, no read endpoint)      │
│  └─────────────┘                                      │
└──────────────────────────────────────────────────────┘
```

**Agent** (`polynumeral-assistant`) — Runs the nanobot `AgentLoop` with a `ZulipChannel` for message routing. Subscribes to configured Zulip streams and responds when @mentioned, then stays engaged in that topic. Has no API keys.

**Credential Proxy** (`polynumeral-cred-proxy`) — A Caddy reverse proxy that holds all API keys and injects auth headers on the way through. Routes to Anthropic, Fastmail, Groq, Brave, and Gmail.

**Log Service** (`polynumeral-log`) — Append-only structured logging. Receives events via POST and writes JSONL to a persistent volume. Has no read endpoint and no secrets.

## Security model

The design assumes the agent processes untrusted input (email bodies, web content, user messages) and could be manipulated via prompt injection. Three layers limit the damage:

### Layer 0: Credential isolation

The agent container has **zero API keys**. All external API access goes through the credential proxy, which injects authentication headers. Even if the agent is fully compromised, it cannot exfiltrate credentials — it literally doesn't have them. The proxy only routes to a fixed set of upstream APIs.

The agent container is further hardened: all Linux capabilities dropped, `no-new-privileges`, read-only filesystem, tmpfs-only scratch space.

### Layer 1: Prompt injection detection

Inbound content (emails, web pages, tool results) is scanned by [LlamaGuard](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) via Groq before entering the agent's context. Long content is chunked and scanned in parallel. If any chunk scores above the malicious threshold, the content is flagged.

Fails open — if Groq is unreachable, the content passes through. Layer 2 is the backstop.

### Layer 2: Action review

Before executing side-effecting tools (`send_email`, `exec`, shell commands, etc.), the proposed action is sent to a safety model (GPT OSS Safeguard 20B on Groq) that checks for dangerous patterns: data exfiltration, credential theft, destructive operations, unexpected network calls.

Blocked actions are logged and the agent receives an error instead of executing.

### Audit trail

Every LLM request/response, tool call/result, guardrail decision, and PromptGuard scan is logged to the append-only log service. The agent can write logs but cannot read or delete them.

## Running locally

```bash
uv sync --dev              # install dependencies
cp .env.example .env       # fill in API keys
docker compose up          # starts all three containers
```

The local setup mirrors production: the agent routes through a local Caddy instance and never sees raw API keys.

## Running tests

```bash
uv run pytest              # all tests
uv run pytest -k "zulip"   # filter by name
```

## Deploying

Three Fly.io apps in `iad`, deployed sequentially (log service, then proxy, then agent):

```bash
./deploy.sh                # sync secrets from .env + deploy all three
./deploy.sh --skip-secrets # code-only deploy
./deploy.sh --dry-run      # preview
```

## Key dependencies

- [`nanobot-ai`](https://github.com/HKUDS/nanobot) — agent framework (sessions, memory, tool execution, LLM calls)
- [`zulip`](https://pypi.org/project/zulip/) — Zulip bot SDK
- [`httpx`](https://www.python-httpx.org/) — async HTTP client
- [Caddy](https://caddyserver.com/) — credential proxy
