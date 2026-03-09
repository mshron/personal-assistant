#!/bin/sh
set -e

# Start Caddy
su-exec caddy caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!

# Only start sidecar if Gmail credentials are present
SIDECAR_PID=""
if [ -n "$GMAIL_APP_PASSWORD" ] && [ -n "$GMAIL_ADDRESS" ]; then
    su-exec gmailproxy python3 /opt/gmail-imap-proxy.py &
    SIDECAR_PID=$!
    echo "[start-proxy] Gmail IMAP sidecar started (PID $SIDECAR_PID)"
else
    echo "[start-proxy] Gmail credentials not set, sidecar not started"
fi

cleanup() {
    kill "$CADDY_PID" $SIDECAR_PID 2>/dev/null || true
    wait "$CADDY_PID" $SIDECAR_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Wait for Caddy (essential process)
wait "$CADDY_PID" 2>/dev/null || true
echo "[start-proxy] Caddy exited, shutting down..."
cleanup
