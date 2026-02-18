# Personal AI Agent — Architecture Design

## Goal

Build a self-hosted personal AI agent that can:
- Communicate over Zulip (primary interface)
- Read and write email
- Do web research
- Make purchases via Privacy.com virtual debit cards
- Kick off Claude Code instances for coding tasks

The emphasis is on **security**, **minimal ops**, and **riding community momentum** rather than building from scratch.

## Constraints

- **Budget**: $40-80/mo infrastructure (excluding API costs)
- **Ops tolerance**: Minimal. Set up once, deploy with a command, auto-restart on failure.
- **Primary threat model**: Compromised agent via prompt injection. Not host-level compromise.
- **Hosting plan**: Start on Fly.io for 2-3 months to build and validate the system, then migrate to a Mac Mini (~$400-500 used M4 16GB) for permanent hosting. Architecture must use Docker Compose so it runs identically in both environments.

---

## 1. Overall Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Fly.io Private Network                │
│                                                         │
│  ┌─────────────────┐    ┌──────────────┐               │
│  │   Nanobot Agent  │───▸│  Tokenizer   │──▸ Upstream   │
│  │  + Zulip channel │    │  (Go proxy)  │    APIs       │
│  │  + Email channel │    └──────────────┘               │
│  │  + MCP tools     │                                   │
│  └────────┬─────────┘    ┌──────────────┐               │
│           │              │  Log Service  │               │
│           ├─────────────▸│ (append-only) │               │
│           │              └──────────────┘               │
│           │                                             │
│           │  on-demand   ┌──────────────┐               │
│           └─────────────▸│ Claude Code   │              │
│              Fly Machine │ (burst, tear  │              │
│              API call    │  down after)  │              │
│                          └──────────────┘               │
└─────────────────────────────────────────────────────────┘
         ▲                          │
         │ Zulip API                │ API calls via
         │ (your messages)          │ Tokenizer
         ▼                          ▼
    Zulip Cloud              Anthropic, Gmail,
                             Privacy.com, etc.
```

**Phase 1 (months 1-3)**: Everything runs on Fly.io's private network. The agent container talks to upstream APIs exclusively through Tokenizer, which injects real credentials per-request. The agent never holds plaintext API keys.

**Phase 2 (month 3+)**: The same Docker Compose stack moves to a Mac Mini on your home network. Fly.io is replaced by a Tailscale mesh network for secure container-to-container communication. The Mac also provides access to local apps, SMS, and filesystem — capabilities that were unavailable on Fly.

```
Phase 2: Mac Mini (home network)
┌─────────────────────────────────────────────────────────┐
│              Docker Compose on Mac Mini                  │
│                                                         │
│  ┌─────────────────┐    ┌──────────────┐               │
│  │   Nanobot Agent  │───▸│  Tokenizer   │──▸ Upstream   │
│  │  + Zulip channel │    │  (Go proxy)  │    APIs       │
│  │  + Email channel │    └──────────────┘               │
│  │  + MCP tools     │                                   │
│  └────────┬─────────┘    ┌──────────────┐               │
│           │              │  Log Service  │               │
│           ├─────────────▸│ (append-only) │               │
│           │              └──────────────┘               │
│           │                                             │
│           │  local or    ┌──────────────┐               │
│           └─────────────▸│ Claude Code   │              │
│              on-demand   │ (local, or    │              │
│                          │  Fly burst)   │              │
│                          └──────────────┘               │
└─────────────────────────────────────────────────────────┘
         ▲                          │
         │ Zulip API                │ Tailscale for
         │ (via Tailscale)          │ secure access
         ▼                          ▼
    Zulip Cloud              Anthropic, Gmail,
                             Privacy.com, etc.
```

---

## 2. Agent Framework: Nanobot

**Choice**: Use Nanobot (github.com/HKUDS/nanobot) as-is.

**Why**:
- Python, ~3.7k lines core, auditable in a sitting
- Already has email (IMAP/SMTP) and Slack channels
- MCP support added Feb 14, 2026
- 21k stars, multiple commits per day, active community
- Adding Zulip means writing one `zulip.py` file following the `BaseChannel` interface (Slack channel is an 8.6KB template)

**Known risk**: Nanobot has a ClawHub skill marketplace — the same pattern that made OpenClaw a security problem. Mitigation: disable ClawHub skills via config, rely on our own guardrails layer (Section 4) rather than trusting the framework's trust model.

**What we add**:
- `zulip.py` channel: Zulip bot that listens on configured streams/DMs, translates to Nanobot's message format
- MCP tool definitions for: web research, Privacy.com purchases, Claude Code invocation
- Configuration to route all HTTP through Tokenizer

**What we don't change**: The core agent loop, conversation memory, context management, multi-turn tool use. These are solved problems in Nanobot.

---

## 3. Credential Security: Fly Tokenizer

**Choice**: Fly Tokenizer (github.com/superfly/tokenizer) as the credential proxy for all API access.

**How it works**:
1. At setup time, real API secrets are encrypted to Tokenizer's Curve25519 public key
2. The agent sends HTTP requests through Tokenizer with encrypted `Proxy-Tokenizer` headers
3. Tokenizer decrypts and injects the real credential into the outbound request
4. The agent process never sees the plaintext key, even in memory

**Per-secret host allowlists**: Each encrypted secret is bound to specific destination hosts. An Anthropic key encrypted for `api.anthropic.com` cannot be used to make requests to `evil.com`. This is the strongest defense against exfiltration — even if the agent is fully compromised via prompt injection, it cannot use a tokenized credential against an unauthorized host.

**Secrets managed through Tokenizer**:

| Secret | Bound to host(s) | Purpose |
|---|---|---|
| Anthropic API key | `api.anthropic.com` | LLM calls |
| Gmail OAuth token | `gmail.googleapis.com` | Email read/write |
| Privacy.com API key | `api.privacy.com` | Virtual card management, purchases |
| Zulip bot API key | `<your-zulip-domain>` | Bot communication |
| Groq API key | `api.groq.com` | PromptGuard inference |
| Fly Machines API token | `api.machines.dev` | Spawning Claude Code instances |

**OAuth flow**: For Gmail, use ssokenizer (github.com/superfly/ssokenizer) to handle the OAuth dance. It performs the token exchange and returns the token already encrypted for Tokenizer. Token refresh follows the same path — the agent never sees the plaintext OAuth token.

**Deployment**: Tokenizer runs as a separate container in the same Docker Compose stack. It is not exposed to the internet — only reachable by other containers on the Docker internal network (via service name `tokenizer`). This works identically on Fly.io and on a Mac Mini.

---

## 4. Guardrails: Three Defense Layers

The primary threat is prompt injection — malicious content in email bodies or web pages that redirects agent behavior.

### Layer 1: Input Scanning (PromptGuard via Groq)

**Choice**: Use Groq's hosted PromptGuard 2 86M endpoint rather than running locally.

**Why not local**:
- Running locally requires 700MB-1GB RAM, pushing the persistent machine to 8GB (~$48/mo)
- Groq endpoint is sub-10ms, free tier likely sufficient for personal use
- The content is already leaving our infrastructure anyway (going to Anthropic, Gmail, etc.), so the privacy tradeoff is negligible

**What it scans**:
- Inbound email bodies before they enter the agent's context
- Web page content fetched during research tasks
- Any external content injected via MCP tools

**On detection**: Flag the content, log it, and either reject or present it to the user via Zulip with a warning. Do not silently pass suspected injections to Claude.

### Layer 2: Action Review (pre-tool-call check)

Before executing any tool call with external side effects (sending email, making a purchase, posting to Zulip on your behalf), run a lightweight alignment check:

- Send the original user intent + the proposed action to Claude Haiku
- Ask: "Does this action align with the user's stated intent? Flag anything suspicious."
- Specific patterns to flag:
  - Outbound requests to unexpected domains
  - Email sends where the recipient wasn't in the original request
  - Purchase amounts exceeding a threshold (configurable, e.g. $50)
  - Large data payloads assembled before an outbound call

This adds ~100-200ms per side-effecting tool call and costs fractions of a cent per check.

### Layer 3: Tokenizer Host Allowlists (network-level)

Already described in Section 3. This is the backstop: even if Layers 1 and 2 fail, a compromised agent cannot use any credentialed API against an unauthorized host. This is passive — no runtime cost, no false positives.

### What we're NOT doing

- **Network allowlisting / egress filtering**: Rejected because it would break web research. The agent needs to fetch arbitrary URLs.
- **WASM sandboxing**: Adds complexity without addressing the primary threat (prompt injection doesn't need code execution to be dangerous).
- **Running PromptGuard locally**: Not worth the RAM cost for a personal agent.

---

## 5. Hosting: Two Phases

### Phase 1: Fly.io (months 1-3)

Fly.io for the initial build-and-validate period. The goal is to get the agent working without also debugging home networking, power reliability, and launchd configuration.

**Why Fly.io for Phase 1 (not DigitalOcean)**:

| Concern | DigitalOcean Droplet | Fly.io |
|---|---|---|
| Ops burden | You manage the OS, Docker, updates, monitoring | Fly manages the VM, restarts on crash, health checks built in |
| Deploy workflow | SSH + docker compose up | `fly deploy` from local machine |
| Private networking | Docker internal network (single host only) | Built-in private network across all machines in the org |
| Burst compute | Need a separate provider | Fly Machines API — same platform, same private network |
| Cost (4GB persistent) | ~$24/mo | ~$31/mo |

One Fly Machine running three processes:

| Process | RAM | Role |
|---|---|---|
| Nanobot agent | ~1-2GB | Agent loop, Zulip/email channels, MCP tools |
| Tokenizer | ~50MB | Credential proxy (stateless Go binary) |
| Log service | ~50MB | Append-only HTTP POST endpoint |

**Total**: 4GB Machine (`shared-cpu-4x`), 10GB persistent volume for SQLite and logs.

**Burst Claude Code**: Ephemeral Fly Machines (16GB) spun up on demand via the Fly Machines API. Same private network, so they reach Tokenizer on the internal network. ~$0.12/hr, torn down after each task.

**Phase 1 cost**: ~$36-37/mo. Total Fly.io spend over 2-3 months: **~$75-110**.

### Phase 2: Mac Mini (month 3+)

Buy a used Mac Mini M4 16GB (~$400-500) and move the entire stack home. The architecture is Docker Compose throughout, so migration is:

1. Install Docker on the Mac Mini
2. Copy `docker-compose.yml`, Tokenizer keypair, and encrypted secrets
3. `docker compose up`
4. Point Zulip bot webhook to the Mac's public address (via Tailscale or Cloudflare Tunnel)
5. Migrate SQLite database and logs from Fly volume

**What changes at migration**:

| Component | Phase 1 (Fly.io) | Phase 2 (Mac Mini) |
|---|---|---|
| Container orchestration | Fly Machines | Docker Compose |
| Private networking | Fly internal network | Docker internal network (single host) |
| External access | Fly handles ingress | Tailscale mesh or Cloudflare Tunnel |
| Auto-restart | Fly built-in | Docker `restart: unless-stopped` + launchd |
| Claude Code burst | Ephemeral Fly Machines | Run locally (16GB is tight but workable for single-agent) or keep Fly for heavy tasks |
| Monitoring | Fly dashboard | Zulip health stream + `docker stats` |

**What doesn't change**: Tokenizer, the agent code, tool definitions, guardrails, log service. The `docker-compose.yml` is the same file in both phases.

**What you gain on Mac**:
- No recurring hosting cost (~$2/mo electricity vs. ~$37/mo Fly)
- Access to local apps, filesystem, SMS (via shortcuts or AppleScript tools)
- 16GB unified memory — enough to run Claude Code locally for most tasks
- Full physical control over the hardware

**What you lose**:
- Uptime depends on your home power and internet
- No Fly dashboard (replaced by Zulip health stream and Docker's built-in restart policies)
- Slightly more setup for external access (one-time Tailscale or Cloudflare Tunnel config)

**Claude Code on Mac**: The Mac Mini M4 has 16GB unified memory. The persistent agent stack uses ~2GB, leaving ~14GB for Claude Code. This is enough for single-agent Claude Code tasks. For heavy multi-subagent tasks (16GB+), either: (a) stop the agent temporarily to free RAM, or (b) keep a Fly.io account and spin up burst machines for those jobs (~$2-5/mo if infrequent).

**Total cost of ownership**:
- Phase 1 (3 months Fly.io): ~$110
- Phase 2 (Mac Mini): ~$450 one-time + ~$2/mo electricity
- **Break-even vs. staying on Fly forever: ~14 months from project start**

### Key Design Constraint: Portability

Because of the planned migration, **everything must run as Docker Compose from day one**. On Fly.io, `fly deploy` wraps the same Dockerfile. On Mac Mini, `docker compose up` runs it directly. No Fly-specific APIs in the agent code itself — the only Fly-specific piece is the `run_claude_code` tool's use of the Fly Machines API, which gets swapped to a local `docker run` invocation at migration time.

---

## 6. Tool Integrations

### Email (Nanobot built-in)

Nanobot already has an email channel (`email.py`, ~14KB). Configure with IMAP/SMTP credentials (OAuth tokens via ssokenizer, proxied through Tokenizer). The agent can read incoming mail and compose replies.

### Zulip (new channel to write)

Write `zulip.py` following Nanobot's `BaseChannel` interface. The Zulip bot:
- Connects via Zulip's bot API (long-polling or event queue)
- Listens on configured streams and DMs
- Translates Zulip messages to Nanobot's internal message format
- Posts agent responses back to the same stream/thread

Zulip API key managed through Tokenizer.

### Web Research (MCP tool)

Expose a `web_research` MCP tool that:
- Takes a query string
- Fetches and processes web pages (using a headless browser or simple HTTP + readability extraction)
- Passes fetched content through PromptGuard Layer 1 before injecting into context
- Returns summarized results to the agent

### Privacy.com Purchases (MCP tool)

Expose a `make_purchase` MCP tool that:
- Creates a single-use virtual card via Privacy.com API (through Tokenizer)
- Sets a per-transaction limit (configurable, e.g. $50 max)
- Returns card details to the agent for use
- Logs the transaction to the append-only log

**Guardrail**: This tool triggers Layer 2 action review (Haiku alignment check) before every execution. Purchases above the configured threshold require explicit Zulip confirmation from the user.

### Claude Code (Fly Machines burst)

Expose a `run_claude_code` MCP tool as described in Section 5. The agent can kick off coding tasks, monitor progress via the log service, and report results back through Zulip.

---

## 7. Append-Only Logging

A minimal service (50-100 lines of Go or Python) running on the persistent Machine:
- Exposes an HTTP POST endpoint on the private network
- Writes each log entry as a JSON line to an append-only file on the persistent volume
- The agent container has write-only access (HTTP POST only, no GET/DELETE)
- Logs are queryable by you via `fly ssh console` or a separate read-only endpoint authenticated to your SSH key

**What gets logged**:
- Every tool call (name, arguments, result summary)
- Every PromptGuard scan result
- Every Layer 2 action review result
- Every Tokenizer-proxied request (destination host, not the credential)
- Agent errors and restarts

**Retention**: Keep everything. At typical personal agent usage, logs will be <1GB/year.

---

## 8. Deployment & Day-to-Day Operations

### Initial Setup

1. Create Fly.io org and app
2. Generate Tokenizer keypair, encrypt all API secrets to its public key
3. Write `fly.toml` and `Dockerfile` for the persistent stack
4. Write `zulip.py` channel for Nanobot
5. `fly deploy` — persistent stack is live
6. Test: send a Zulip message, verify agent responds via Claude through Tokenizer

### Deploying Updates

```
fly deploy
```

Fly handles rolling restart. Zero-downtime for a single-machine setup isn't critical (personal agent, seconds of downtime is fine).

### Monitoring

- Append-only logs capture all agent actions
- Zulip `#agent-health` stream receives posts on: restarts, guardrail trips, errors
- Phase 1: Fly dashboard for Machine health and resource usage
- Phase 2: `docker stats` and the Zulip health stream
- No pager-duty. Check the health stream when you feel like it.

### Migration to Mac Mini (end of Phase 1)

Checklist for moving the stack from Fly.io to a Mac Mini:

1. **Set up the Mac Mini**: Install Docker Desktop (or OrbStack), Tailscale, and configure the Mac to stay awake with lid closed (if using a Mac Mini, this is default)
2. **Set up external access**: Install Tailscale on the Mac. The agent reaches Zulip Cloud via outbound HTTPS (no inbound ports needed). If Zulip webhooks need to reach the agent, use Cloudflare Tunnel or Tailscale Funnel for a stable public endpoint.
3. **Copy the stack**: `docker-compose.yml`, Tokenizer keypair, encrypted secrets, `.env` file. These are the same files used on Fly.
4. **Migrate data**: Copy SQLite database and log files from the Fly volume (`fly ssh sftp get`)
5. **Start the stack**: `docker compose up -d`
6. **Update DNS / webhooks**: Point any external webhooks (Zulip, Gmail push notifications) to the new address
7. **Swap Claude Code tool**: Change `run_claude_code` from Fly Machines API to local `docker run` (or keep Fly for heavy tasks)
8. **Verify**: Send a Zulip message, confirm the agent responds
9. **Tear down Fly.io**: `fly apps destroy` once everything is confirmed working
10. **Set up auto-start**: Configure Docker to start on boot, add a launchd plist to restart on crash

**Estimated migration time**: A few hours, mostly waiting for data transfer and DNS propagation.

---

## 9. Decisions Deferred

These are questions to answer during implementation, not upfront:

- **Memory/persistence strategy**: Nanobot has built-in conversation memory via SQLite. Start with that, evaluate whether you need something more sophisticated after real usage.
- **PromptGuard false positive tuning**: Run it on real email content during the first week. If false positives are a problem, add a Zulip confirmation flow ("PromptGuard flagged this email — process anyway?").
- **Spend tracking**: Start without LiteLLM. Track API spend via Anthropic's dashboard and Fly's billing. Add LiteLLM later only if you need virtual keys or per-task cost attribution.
- **Zulip permission model**: Start with DMs only (agent responds to your direct messages). Add stream-based interaction later if useful.
- **OAuth token refresh**: ssokenizer handles the initial OAuth dance. For refresh, test whether ssokenizer's refresh flow works end-to-end before building a custom solution.
- **Mac Mini model**: M4 16GB (~$450) is the default choice. Decide closer to migration whether 16GB is enough based on actual Claude Code usage patterns during Phase 1.
- **Claude Code after migration**: Run locally if 16GB suffices, keep a minimal Fly account for burst if it doesn't. Decide based on Phase 1 usage data.

---

## 10. Implementation Order

### Phase 1: Build and validate on Fly.io (months 1-3)

1. **Nanobot + Zulip on Fly.io** — get the agent talking to you. No security layers yet. Anthropic key as a Fly secret (not ideal but gets you running).
2. **Tokenizer** — add the credential proxy. Re-encrypt the Anthropic key. Verify agent still works through Tokenizer.
3. **Email** — configure Nanobot's email channel. Set up ssokenizer for Gmail OAuth.
4. **PromptGuard** — add input scanning via Groq. Test on real email.
5. **Action review** — add Haiku-based pre-tool-call checks for side-effecting tools.
6. **Append-only logging** — add the log service. Wire all tool calls through it.
7. **Web research tool** — add the MCP tool with PromptGuard scanning on fetched content.
8. **Privacy.com purchases** — add the MCP tool with hard limits and Zulip confirmation.
9. **Claude Code burst** — add the Fly Machines invocation tool.

Each step is independently deployable and testable. You have a working agent after step 1.

### Phase 2: Migrate to Mac Mini (month 3+)

10. **Buy Mac Mini** — used M4 16GB, ~$400-500.
11. **Set up Mac** — Docker, Tailscale, auto-start configuration.
12. **Migrate stack** — copy Docker Compose stack, Tokenizer keys, data. Follow the migration checklist in Section 8.
13. **Swap Claude Code tool** — local `docker run` instead of Fly Machines API.
14. **Tear down Fly.io** — once confirmed working, destroy the Fly app.
15. **Add Mac-local tools** — local filesystem access, SMS via Shortcuts, local app automation. These are new capabilities that weren't possible on Fly.
