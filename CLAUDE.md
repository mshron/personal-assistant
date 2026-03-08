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
cp .env.example .env       # fill in API keys (used by credential proxy)
docker compose up          # starts credential-proxy, log-service, and agent
```

The agent always routes through the credential proxy (Caddy), even locally. `docker-compose.yml` runs a local Caddy instance that reads API keys from `.env` and exposes `CRED_PROXY_BASE=http://credential-proxy:8080` to the agent. The agent container never sees raw API keys (except `KAGI_API_KEY` — see exception below).

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

**NEVER read, open, grep, or cat the `.env` file.** It contains live secrets and must only be edited by the user directly.

- **Local dev**: API keys live in `.env`, which docker-compose passes to the credential-proxy container only. The agent container never sees them.
- **Production**: API keys are set via `fly secrets set` on the `polynumeral-cred-proxy` app. The agent app (`polynumeral-assistant`) gets `CRED_PROXY_BASE` pointing to the proxy's Flycast address.

Key secrets (set on the credential proxy, not the agent):
- `ANTHROPIC_API_KEY` — LLM API key
- `GROQ_API_KEY` — for PromptGuard (LlamaGuard) and Action Review (Safeguard 20B)
- `FASTMAIL_API_TOKEN` — Fastmail JMAP access
- `KAGI_API_KEY` — for Kagi search/summarizer

Agent-side secrets:
- `ZULIP_SITE`, `ZULIP_EMAIL`, `ZULIP_API_KEY` — bot credentials (not proxied)

## Zulip channel behavior

- Bot subscribes to configured streams and uses `all_public_streams=True` for full message delivery
- **@mentions work in any stream** — engages the topic for future monitoring
- **Engaged topics**: once @mentioned in a topic, the bot responds to all subsequent messages without requiring @mention
- **Topic history**: on first message in a topic each session, fetches prior messages via Zulip API and prepends as context
- **Engaged topics persist** across restarts via `/data/zulip_engaged_topics.json`
- `ZULIP_STREAMS` controls which streams get non-@mention monitoring; @mentions bypass this filter

## Security: Credential Isolation

**Design principle**: The agent container must never have direct access to API credentials. All external API access goes through the credential proxy.

`CRED_PROXY_BASE` is required. It points to a Caddy reverse proxy that holds all real API tokens — `polynumeral-cred-proxy` on Fly.io in production, or the `credential-proxy` docker-compose service locally. The agent sends requests to the proxy, which injects auth headers and forwards to the real APIs. This is defense-in-depth: even if the agent is compromised via prompt injection, it cannot exfiltrate credentials.

**When adding new external API integrations**: Add a route in `credential-proxy/Caddyfile`, then have the client code derive its base URL from `CRED_PROXY_BASE`. No direct API key fallbacks. See `docs/credential-proxy-options.md` for handling third-party libraries that hardcode URLs.

## Key env vars

**Agent container env vars:**

| Variable | Purpose |
|----------|---------|
| `CRED_PROXY_BASE` | **Required.** Credential proxy URL (e.g. `http://credential-proxy:8080` locally, `http://polynumeral-cred-proxy.flycast:8080` in prod) |
| `AGENT_MODE` | `cli` (default) or `zulip` |
| `ZULIP_SITE` | e.g. `https://polynumeral.zulipchat.com` |
| `ZULIP_EMAIL` | Bot email |
| `ZULIP_API_KEY` | Bot API key |
| `ZULIP_STREAMS` | Streams to monitor (comma-separated) |
| `ZULIP_ALLOW_FROM` | Optional sender ID allowlist |
| `ACTION_REVIEW_MODEL` | Groq model for action review (default: `openai/gpt-oss-safeguard-20b`) |
| `EMAIL_SUBSCRIPTIONS_FILE` | Path for subscription state (default: `/data/email_subscriptions.json`) |
| `RATE_LIMIT_TPM` | Token-bucket rate limit (tokens/min); 0 = off |
| `LOG_FILE` | Path for audit log JSONL |
| `LOG_SERVICE_URL` | URL of log-service sidecar |

**Credential proxy env vars** (set in `.env` for local, `fly secrets set` for prod):

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | LLM API key |
| `GROQ_API_KEY` | For PromptGuard + Action Review |
| `FASTMAIL_API_TOKEN` | Fastmail JMAP access |
| `KAGI_API_KEY` | Kagi search/summarizer |

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

# Beads

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds


<!-- BEGIN BEADS INTEGRATION -->
## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

### Why bd?

- Dependency-aware: Track blockers and relationships between issues
- Git-friendly: Dolt-powered version control with native sync
- Agent-optimized: JSON output, ready work detection, discovered-from links
- Prevents duplicate tracking systems and confusion

### Quick Start

**Check for ready work:**

```bash
bd ready --json
```

**Create new issues:**

```bash
bd create "Issue title" --description="Detailed context" -t bug|feature|task -p 0-4 --json
bd create "Issue title" --description="What this issue is about" -p 1 --deps discovered-from:bd-123 --json
```

**Claim and update:**

```bash
bd update <id> --claim --json
bd update bd-42 --priority 1 --json
```

**Complete work:**

```bash
bd close bd-42 --reason "Completed" --json
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

### Creating Issues

Every issue must include a concrete testing plan. Prefer running actual tests to verify correctness before closing — `uv run pytest` for unit tests, `docker compose up` for integration tests, `curl` for API routes. A ticket is not closeable until its tests pass. Include the testing plan in the description or notes when creating the issue.

### Workflow for AI Agents

1. **Check ready work**: `bd ready` shows unblocked issues
2. **Claim your task atomically**: `bd update <id> --claim`
3. **Work on it**: Implement, test, document
4. **Run the testing plan**: Execute the tests described in the issue before closing. Use Docker containers for integration testing when applicable.
5. **Discover new work?** Create linked issue:
   - `bd create "Found bug" --description="Details about what was found" -p 1 --deps discovered-from:<parent-id>`
6. **Complete**: `bd close <id> --reason "Done"`

### Auto-Sync

bd automatically syncs via Dolt:

- Each write auto-commits to Dolt history
- Use `bd dolt push`/`bd dolt pull` for remote sync
- No manual export/import needed!

### Important Rules

- ✅ Use bd for ALL task tracking
- ✅ Always use `--json` flag for programmatic use
- ✅ Link discovered work with `discovered-from` dependencies
- ✅ Check `bd ready` before asking "what should I work on?"
- ❌ Do NOT create markdown TODO lists
- ❌ Do NOT use external issue trackers
- ❌ Do NOT duplicate tracking systems

For more details, see README.md and docs/QUICKSTART.md.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

<!-- END BEADS INTEGRATION -->
