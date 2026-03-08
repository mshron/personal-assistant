# Three-App Fly.io Deployment with deploy.sh

## Problem

The agent container currently bundles the log service as a sidecar process. This means:
- A compromised agent can read/tamper with its own audit logs
- Logs don't survive agent container rebuilds
- Zulip credentials sit in fly.toml instead of fly secrets

Additionally, there's no single command to deploy the full stack with secrets.

## Design

### Three Fly Apps

| App | Purpose | Secrets | Volume |
|-----|---------|---------|--------|
| `polynumeral-log` | Append-only POST endpoint, JSONL to volume | None | `log_data` at `/data` |
| `polynumeral-cred-proxy` | Caddy reverse proxy, injects auth headers | API keys (Anthropic, Groq, Fastmail, Kagi) |  None |
| `polynumeral-assistant` | Agent + MCP servers | Zulip creds only | `agent_data` at `/data` |

### Network

All three on Fly private network (Flycast). Agent reaches:
- Log service at `http://polynumeral-log.flycast/log`
- Cred proxy at `http://polynumeral-cred-proxy.flycast`

No apps exposed to the public internet.

### deploy.sh

Sequential deployment with secret sync:

1. Parse `.env` for secret values (never echo them)
2. `fly secrets set --stage` on polynumeral-cred-proxy (API keys)
3. `fly secrets set --stage` on polynumeral-assistant (Zulip creds)
4. Deploy polynumeral-log, wait for healthy
5. Deploy polynumeral-cred-proxy, wait for healthy
6. Deploy polynumeral-assistant
7. Tail agent logs to verify startup

Flags: `--dry-run` (print plan without executing), `--skip-secrets` (code-only deploy).

Secret key lists defined as arrays at top of script for easy modification when adding services.

### Changes from Current State

- Log service: gets its own fly.toml, deployed as separate app
- start.sh: simplified to just `exec uv run python -m personal_agent.main`
- Dockerfile.fly: no longer bundles log-service/main.py
- fly.toml: LOG_SERVICE_URL changes to Flycast address
- Zulip creds: moved from fly.toml [env] to fly secrets
- docker-compose.yml: unchanged (local dev stays the same)

### Adding a New External Service

1. Add route to `credential-proxy/Caddyfile`
2. Add API key to `.env`
3. Add key name to `CRED_PROXY_SECRETS` array in `deploy.sh`
4. Derive base URL from `CRED_PROXY_BASE` in agent code
