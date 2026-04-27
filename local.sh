#!/bin/bash
set -euo pipefail

# Local deployment using Apple container framework (macOS Containers).
# Replaces docker-compose for running the agent stack on a local Mac server.
#
# Usage:
#   ./local.sh start          # Build images and start all services
#   ./local.sh stop           # Stop all containers
#   ./local.sh restart        # Stop + start
#   ./local.sh logs [service] # Tail logs (agent, cred-proxy, log-service)
#   ./local.sh status         # Show container status
#   ./local.sh build          # Rebuild images only
#   ./local.sh destroy        # Stop containers and delete volumes

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

NETWORK="pa-net"
LOG_VOLUME="pa-log-data"
AGENT_VOLUME="pa-agent-data"
ENV_FILE=".env"

# Container names
LOG_SERVICE="pa-log-service"
CRED_PROXY="pa-cred-proxy"
AGENT="pa-agent"

# --- Helpers ---

log() { echo "[local] $*"; }

ensure_system() {
    if ! container system status &>/dev/null; then
        log "Starting container system..."
        brew services start container 2>/dev/null || true
        container system start 2>/dev/null || true
        sleep 2
    fi
}

ensure_network() {
    if ! container network inspect "$NETWORK" &>/dev/null; then
        log "Creating network $NETWORK..."
        container network create "$NETWORK"
    fi
}

ensure_volumes() {
    for vol in "$LOG_VOLUME" "$AGENT_VOLUME"; do
        if ! container volume inspect "$vol" &>/dev/null; then
            log "Creating volume $vol..."
            container volume create "$vol"
        fi
    done
}

get_container_ip() {
    local name="$1"
    container inspect "$name" 2>/dev/null | uv run python -c "
import json, sys
data = json.loads(sys.stdin.read())
for item in data:
    for net in item.get('networks', []):
        ip = net.get('ipv4Address', '')
        if '/' in ip:
            ip = ip.split('/')[0]
        print(ip)
        sys.exit(0)
" 2>/dev/null
}

is_running() {
    container inspect "$1" &>/dev/null 2>&1
}

wait_for_healthy() {
    local name="$1"
    local port="$2"
    local attempts=30
    log "Waiting for $name to be healthy..."
    for i in $(seq 1 $attempts); do
        if container exec "$name" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${port}/health', timeout=2)" 2>/dev/null; then
            log "$name is healthy"
            return 0
        fi
        sleep 1
    done
    log "WARNING: $name health check timed out after ${attempts}s"
    return 1
}

# --- Commands ---

do_build() {
    log "Building images..."
    container build -t "$LOG_SERVICE" log-service/ 2>&1 | tail -1
    container build -t "$CRED_PROXY" credential-proxy/ 2>&1 | tail -1
    container build -t "$AGENT" -m 4096MB . 2>&1 | tail -1
    log "All images built"
}

do_stop() {
    log "Stopping containers..."
    for name in "$AGENT" "$CRED_PROXY" "$LOG_SERVICE"; do
        if is_running "$name"; then
            container stop "$name" 2>/dev/null || true
            container rm "$name" 2>/dev/null || true
            log "Stopped $name"
        fi
    done
}

do_start() {
    if [ ! -f "$ENV_FILE" ]; then
        echo "Error: $ENV_FILE not found. Copy .env.example and fill in your secrets." >&2
        exit 1
    fi

    # Read specific host-side config from .env (without sourcing secrets)
    OBSIDIAN_VAULT_PATH=$(grep -E '^OBSIDIAN_VAULT_PATH=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"'"'" || true)

    ensure_system
    ensure_network
    ensure_volumes

    # Stop any existing containers first
    for name in "$AGENT" "$CRED_PROXY" "$LOG_SERVICE"; do
        if is_running "$name"; then
            container stop "$name" 2>/dev/null || true
            container rm "$name" 2>/dev/null || true
        fi
    done

    # 1. Start log service
    log "Starting $LOG_SERVICE..."
    container run -d --name "$LOG_SERVICE" \
        --network "$NETWORK" \
        -e LOG_FILE=/data/agent.jsonl \
        -v "$LOG_VOLUME":/data \
        --tmpfs /tmp:size=16M \
        "$LOG_SERVICE" \
        python main.py

    LOG_IP=$(get_container_ip "$LOG_SERVICE")
    wait_for_healthy "$LOG_SERVICE" 8081

    # 2. Start credential proxy
    log "Starting $CRED_PROXY..."
    container run -d --name "$CRED_PROXY" \
        --network "$NETWORK" \
        --env-file "$ENV_FILE" \
        --tmpfs /data:size=64M \
        --tmpfs /config:size=16M \
        --tmpfs /tmp:size=16M \
        "$CRED_PROXY" \
        caddy run --config /etc/caddy/Caddyfile

    PROXY_IP=$(get_container_ip "$CRED_PROXY")
    sleep 2  # Caddy needs a moment to start

    # 3. Start agent
    log "Starting $AGENT..."

    # Build container run args
    AGENT_ARGS=(
        -d --name "$AGENT"
        --network "$NETWORK"
        --env-file "$ENV_FILE"
        -e "CRED_PROXY_BASE=http://${PROXY_IP}:8080"
        -e "LOG_SERVICE_URL=http://${LOG_IP}:8081/log"
        -e AGENT_MODE=zulip
        -v "$AGENT_VOLUME":/data/nanobot
        --tmpfs /tmp:size=256M
        -m 4096MB
    )

    # Optional: mount Obsidian vault
    if [ -n "${OBSIDIAN_VAULT_PATH:-}" ]; then
        if [ -d "$OBSIDIAN_VAULT_PATH" ]; then
            AGENT_ARGS+=(-v "$OBSIDIAN_VAULT_PATH":/data/obsidian)
            log "Mounting Obsidian vault from $OBSIDIAN_VAULT_PATH"
        else
            log "WARNING: OBSIDIAN_VAULT_PATH set but directory not found: $OBSIDIAN_VAULT_PATH"
        fi
    fi

    container run "${AGENT_ARGS[@]}" "$AGENT"

    AGENT_IP=$(get_container_ip "$AGENT")

    log "All services started:"
    log "  $LOG_SERVICE  → $LOG_IP:8081"
    log "  $CRED_PROXY   → $PROXY_IP:8080"
    log "  $AGENT        → $AGENT_IP"
}

do_status() {
    container list 2>&1 | grep -E "^(ID|pa-)" || echo "No pa- containers running"
}

do_logs() {
    local service="${1:-agent}"
    case "$service" in
        agent)       container logs --follow "$AGENT" 2>&1 ;;
        cred-proxy)  container logs --follow "$CRED_PROXY" 2>&1 ;;
        log-service) container logs --follow "$LOG_SERVICE" 2>&1 ;;
        *)
            echo "Unknown service: $service"
            echo "Valid: agent, cred-proxy, log-service"
            exit 1
            ;;
    esac
}

do_destroy() {
    do_stop
    log "Removing volumes..."
    container volume rm "$LOG_VOLUME" 2>/dev/null || true
    container volume rm "$AGENT_VOLUME" 2>/dev/null || true
    log "Removing network..."
    container network rm "$NETWORK" 2>/dev/null || true
    log "Cleaned up"
}

# --- Main ---

case "${1:-help}" in
    start)   do_build && do_start ;;
    stop)    do_stop ;;
    restart) do_stop && do_build && do_start ;;
    logs)    do_logs "${2:-agent}" ;;
    status)  do_status ;;
    build)   do_build ;;
    destroy) do_destroy ;;
    help|*)
        echo "Usage: $0 {start|stop|restart|logs [service]|status|build|destroy}"
        echo ""
        echo "Commands:"
        echo "  start          Build images and start all services"
        echo "  stop           Stop all containers"
        echo "  restart        Stop, rebuild, and start"
        echo "  logs [service] Tail logs (agent, cred-proxy, log-service)"
        echo "  status         Show container status"
        echo "  build          Rebuild images only"
        echo "  destroy        Stop containers and delete volumes"
        ;;
esac
