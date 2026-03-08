# Credential Proxy: Options for Third-Party MCP Servers

## Problem

The agent container must not hold API credentials. All API access routes through a Caddy reverse proxy (`CRED_PROXY_BASE`). This works when client code can be configured with a custom base URL, but some third-party libraries hardcode their API endpoints (e.g. `kagiapi` hardcodes `https://kagi.com/api/v0`).

## Approaches

### 1. Custom MCP server (current approach for kagi)

Replace the third-party MCP server with our own that uses `httpx` and routes through `CRED_PROXY_BASE`.

- **Pros:** Simple, explicit, same pattern as email MCP server, no extra infrastructure
- **Cons:** Must reimplement each service's tools; doesn't scale if we add many third-party MCP servers
- **When to use:** Service has few tools and a simple API (like kagi: 2 tools)

### 2. MITM forward proxy (general solution, not yet implemented)

Run mitmproxy in the agent container with a custom CA cert. Set `HTTPS_PROXY` on subprocesses. A small addon script intercepts requests and injects auth headers by destination host.

- **Pros:** Works with any MCP server regardless of base URL configurability; one-time setup
- **Cons:** ~100MB added to container (mitmproxy); requires CA cert trust setup for each language runtime:
  - Python: `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` env vars
  - Node.js: `NODE_EXTRA_CA_CERTS` env var
  - One more sidecar process to manage
- **When to use:** Multiple third-party MCP servers that hardcode URLs
- **Note:** Can't use Let's Encrypt — it only issues certs for domains you own. Must generate a self-signed CA.

### 3. Configure base URL (ideal case)

If the client library or MCP server supports a custom base URL or API endpoint, just point it at `CRED_PROXY_BASE/<service>`.

- **Claude Code:** Supports `ANTHROPIC_BASE_URL` env var — works with the proxy out of the box
- **Our own MCP servers (email, kagi):** Built to use `CRED_PROXY_BASE`
- **When to use:** Always prefer this when available

## Decision record

- 2026-03-07: Chose custom MCP server for kagi (2 tools, simple API). Deferred MITM proxy until we have multiple hard-coded third-party servers.
- Claude Code can use `ANTHROPIC_BASE_URL` so it doesn't need MITM.
