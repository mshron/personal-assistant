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

## Agent-Side Changes

- FastmailProvider: accept `api_base` parameter, default to direct URL for local dev
- LiteLLM/Anthropic: use `api_base` pointing to proxy
- Email MCP server: accept FASTMAIL_API_BASE instead of FASTMAIL_API_TOKEN
- Kagi MCP server: CANNOT use reverse proxy. kagimcp uses kagiapi.KagiClient which hardcodes `BASE_URL = "https://kagi.com/api/v0"` as a class variable — no env var override exists. Requires either an HTTP forward proxy (HTTP_PROXY/HTTPS_PROXY) that intercepts kagi.com requests, or a fork/wrapper of kagimcp.
- main.py: inject proxy base URLs instead of tokens into MCP server env

## Fly Deployment

- New Fly app: `polynumeral-cred-proxy`
- Dockerfile: official Caddy image + Caddyfile
- Secrets: all API tokens set on this app only
- Flycast enabled for private networking
- Agent app connects via `http://polynumeral-cred-proxy.flycast:8080`

## Local Development

For local dev, tokens are passed directly (no proxy). The provider classes accept either a token or a base URL, with the token taking precedence. This avoids needing to run Caddy locally.

## Design Principle

The agent container must never have direct access to API credentials. All external API access goes through the credential proxy. This is a defense-in-depth measure: even if the agent is compromised via prompt injection, it cannot exfiltrate credentials.
