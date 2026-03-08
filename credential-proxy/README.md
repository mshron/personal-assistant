# Credential Proxy

Caddy reverse proxy that holds API tokens and injects auth headers on behalf of the agent container. Runs as a separate Fly app on Flycast (private networking), so the agent never has direct access to credentials.

## Routes

| Path prefix   | Upstream                    | Auth header                          |
|---------------|-----------------------------|--------------------------------------|
| `/anthropic/` | `https://api.anthropic.com` | `x-api-key: <ANTHROPIC_API_KEY>`     |
| `/fastmail/`  | `https://api.fastmail.com`  | `Authorization: Bearer <FASTMAIL_API_TOKEN>` |
| `/groq/`      | `https://api.groq.com`      | `Authorization: Bearer <GROQ_API_KEY>` |
| `/kagi/`      | `https://api.kagi.com`      | `Authorization: Bearer <KAGI_API_KEY>` |

## Deploy

From this directory:

```bash
fly apps create polynumeral-cred-proxy
fly secrets set ANTHROPIC_API_KEY=... FASTMAIL_API_TOKEN=... GROQ_API_KEY=... KAGI_API_KEY=...
fly deploy
```

The agent connects via `http://polynumeral-cred-proxy.flycast:8080`.

## Local development

Not needed locally. In local dev the agent uses API tokens directly via environment variables.
