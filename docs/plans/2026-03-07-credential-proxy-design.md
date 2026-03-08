# Credential Proxy: Isolating API Tokens from the Agent

## Problem

All API tokens (Anthropic, Fastmail, Groq, Kagi) are available as env vars in the agent container. A compromised agent (via prompt injection or tool exploit) can read `os.environ` and exfiltrate credentials.

## Solution

Run a Caddy reverse proxy as a separate Fly app on a private network. The proxy holds all real API tokens. The agent container has no tokens — it sends requests to the proxy, which injects auth headers and forwards to the real APIs.

## Architecture

```
Fly App: credential-proxy              Fly App: polynumeral-assistant
(has all real API tokens)               (has NO real tokens)

Caddy reverse proxy                     Agent process
  /anthropic/* -> api.anthropic.com       ANTHROPIC_API_BASE=http://cred-proxy.flycast/anthropic
  /fastmail/* -> api.fastmail.com         FASTMAIL_API_BASE=http://cred-proxy.flycast/fastmail
  /groq/*    -> api.groq.com             GROQ_API_BASE=http://cred-proxy.flycast/groq
  /kagi/*    -> api.kagi.com             KAGI_API_BASE=http://cred-proxy.flycast/kagi

Private Flycast network (not internet-routable)
```

## Caddy Configuration

Each route:
1. Strips the service prefix from the path
2. Adds the appropriate auth header (Bearer token, x-api-key, etc.)
3. Reverse-proxies to the real API over HTTPS

Example for Fastmail:
```
:8080 {
    handle_path /fastmail/* {
        reverse_proxy https://api.fastmail.com {
            header_up Authorization "Bearer {env.FASTMAIL_API_TOKEN}"
            header_up Host api.fastmail.com
        }
    }
    handle_path /anthropic/* {
        reverse_proxy https://api.anthropic.com {
            header_up x-api-key {env.ANTHROPIC_API_KEY}
            header_up Host api.anthropic.com
        }
    }
    # ... groq, kagi similarly
}
```

## Agent-Side Changes (implemented)

- FastmailProvider: proxy-only, requires `api_base` (no direct token mode)
- LiteLLM/Anthropic: uses `api_base` pointing to proxy
- Email MCP server: requires FASTMAIL_API_BASE (derived from CRED_PROXY_BASE)
- Kagi MCP server: custom implementation replacing kagimcp, routes through CRED_PROXY_BASE/kagi
- main.py: requires CRED_PROXY_BASE, injects proxy base URLs into MCP server env

## Fly Deployment

- New Fly app: `polynumeral-cred-proxy`
- Dockerfile: official Caddy image + Caddyfile
- Secrets: all API tokens set on this app only
- Flycast enabled for private networking
- Agent app connects via `http://polynumeral-cred-proxy.flycast`

## Local Development

Local dev uses `docker compose up`, which runs a Caddy credential-proxy container reading API keys from `.env`. The agent container gets `CRED_PROXY_BASE=http://credential-proxy:8080` — same code path as production, no dual-mode fallbacks.

## Design Principle

The agent container must never have direct access to API credentials. All external API access goes through the credential proxy. This is a defense-in-depth measure: even if the agent is compromised via prompt injection, it cannot exfiltrate credentials.
