# Gmail OAuth2 Token Refresh Proxy

## Problem

The Gmail REST API requires OAuth2 Bearer tokens that expire every hour. The credential proxy (Caddy) can only inject static headers. Personal @gmail.com accounts cannot use service accounts — they require the OAuth2 web server flow with a refresh token.

## Solution

A small Python sidecar process runs alongside Caddy in the `polynumeral-cred-proxy` container. It handles OAuth2 token refresh and proxies Gmail API requests with fresh access tokens. Caddy routes `/gmail/*` to the sidecar.

## Architecture

```
Agent container                    Proxy container
                                   ┌─────────────────────────────────┐
                                   │ Caddy (caddy user, port 8080)   │
 GET /gmail/v1/users/me/messages ──┤  /anthropic/* → anthropic.com   │
                                   │  /fastmail/* → fastmail.com     │
                                   │  /gmail/*    → localhost:8081   │
                                   │                                 │
                                   │ gmail-token-proxy               │
                                   │  (gmailproxy user, port 8081)   │
                                   │  binds 127.0.0.1 only           │
                                   │  holds: refresh token,          │
                                   │         client_id, secret       │
                                   │  caches access token in RAM     │
                                   │  forwards to googleapis.com     │
                                   └─────────────────────────────────┘
```

## Token Refresh Logic

- Uses `google-auth` library for token management (handles refresh, retry, clock skew)
- Caches access token in memory; refreshes when <5 minutes from expiry
- On first request: exchanges refresh token for access token via `POST https://oauth2.googleapis.com/token`
- On `invalid_grant` error: logs error, returns 502 with JSON body, alerts via stderr (visible in `fly logs`)
- On Google 401 response: force-refreshes token, retries once

## OAuth2 Scopes

- `gmail.readonly` — list, search, read messages and headers
- `gmail.send` — send unsubscribe emails

Not included (add later if needed): `gmail.modify` (labels, archive, delete), `gmail.compose` (drafts).

## Secrets

Three new secrets on `polynumeral-cred-proxy`:

| Secret | Purpose |
|--------|---------|
| `GMAIL_REFRESH_TOKEN` | Long-lived OAuth2 refresh token |
| `GMAIL_CLIENT_ID` | GCP OAuth2 client ID |
| `GMAIL_CLIENT_SECRET` | GCP OAuth2 client secret |

These replace the single `GMAIL_ACCESS_TOKEN` from the previous design.

## Hardening

- **Separate user**: `gmailproxy` — no login shell, no home dir, no sudo
- **Caddy runs as `caddy`** (not root)
- **Localhost only**: sidecar binds `127.0.0.1:8081`, unreachable from outside container
- **Read-only filesystem**: same `read_only: true` as docker-compose, tmpfs for runtime state
- **Minimal deps**: `google-auth` + `httpx` only, no web framework
- **Secrets isolation**: only sidecar process reads Gmail OAuth creds; Caddy never sees them
- **Process supervisor**: entrypoint script launches both Caddy and sidecar, drops privileges

## Container Changes

The proxy container currently runs only Caddy (Alpine-based). Changes:

1. Switch to a multi-stage Dockerfile: Alpine base + Python for the sidecar
2. Create `gmailproxy` user in Dockerfile
3. Add `gmail-token-proxy.py` (single file, ~80 lines)
4. Add `start-proxy.sh` entrypoint that launches both processes
5. Install `google-auth` and `httpx` via pip (in build stage)

## Caddyfile Change

Replace the static Gmail route:

```
handle_path /gmail/* {
    reverse_proxy localhost:8081
}
```

No auth header injection — the sidecar handles it.

## Setup Flow (One-Time)

1. Create a GCP project (or reuse existing)
2. Enable Gmail API
3. Create OAuth2 credentials (Desktop app type)
4. Set consent screen to "External" + "Testing", add your email as test user
5. Run a local authorization script that opens browser, you consent, get refresh token
6. Store refresh token, client ID, client secret in `.env`
7. `./deploy.sh` distributes them to the proxy

Token expires every 7 days in Testing mode. On `invalid_grant`, re-run the authorization script (~30 seconds). The bot can detect this and alert on Zulip.

For Workspace accounts: set consent screen to "Internal" — no expiry, no review needed.

## Local Development

`docker-compose.yml` passes `GMAIL_REFRESH_TOKEN`, `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET` to the proxy container. Same code path as production.

## Files to Create/Modify

### New files
- `credential-proxy/gmail-token-proxy.py` — sidecar HTTP server (~80 lines)
- `credential-proxy/start-proxy.sh` — entrypoint launching Caddy + sidecar
- `scripts/gmail-authorize.py` — one-time OAuth2 consent script

### Modified files
- `credential-proxy/Dockerfile` — multi-stage, add Python, gmailproxy user, sidecar
- `credential-proxy/Caddyfile` — route /gmail/* to localhost:8081
- `deploy.sh` — replace GMAIL_ACCESS_TOKEN with GMAIL_REFRESH_TOKEN, GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET
- `docker-compose.yml` — update proxy env vars
- `.env.example` — update Gmail vars
- `credential-proxy/README.md` — document new architecture

### No changes needed
- `personal_agent/email/gmail.py` — GmailProvider is unchanged, still sends HTTP to proxy
- `personal_agent/main.py` — GMAIL_API_BASE injection unchanged
- Agent container — no changes at all
