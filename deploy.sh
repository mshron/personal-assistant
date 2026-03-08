#!/usr/bin/env bash
# Deploy all three Fly apps with secrets from .env.
# Usage: ./deploy.sh [--dry-run] [--skip-secrets]
set -euo pipefail

# ---------------------------------------------------------------------------
# App names
# ---------------------------------------------------------------------------
LOG_APP="polynumeral-log"
PROXY_APP="polynumeral-cred-proxy"
AGENT_APP="polynumeral-assistant"

# ---------------------------------------------------------------------------
# Secret mappings — add new services here
# ---------------------------------------------------------------------------
# Keys from .env to set on the credential proxy app:
CRED_PROXY_SECRETS=(
    ANTHROPIC_API_KEY
    GROQ_API_KEY
    FASTMAIL_API_TOKEN
    KAGI_API_KEY
)

# Keys from .env to set on the agent app:
AGENT_SECRETS=(
    ZULIP_SITE
    ZULIP_EMAIL
    ZULIP_API_KEY
)

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
DRY_RUN=false
SKIP_SECRETS=false

for arg in "$@"; do
    case "$arg" in
        --dry-run)    DRY_RUN=true ;;
        --skip-secrets) SKIP_SECRETS=true ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--skip-secrets]"
            echo "  --dry-run       Print plan without executing"
            echo "  --skip-secrets  Skip secret setting (code-only deploy)"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
step() { echo "==> $*"; }

run() {
    if $DRY_RUN; then
        echo "    [dry-run] $*"
    else
        "$@"
    fi
}

# Read a value from .env (handles KEY=VALUE and KEY="VALUE" formats).
# Returns empty string if not found.
read_env() {
    local key="$1"
    local env_file="${2:-.env}"
    if [[ ! -f "$env_file" ]]; then
        echo ""
        return
    fi
    # Match KEY=VALUE, stripping optional quotes
    local val
    val=$(grep -E "^${key}=" "$env_file" 2>/dev/null | head -1 | sed "s/^${key}=//" | sed 's/^["'"'"']//;s/["'"'"']$//')
    echo "$val"
}

# Set secrets on a Fly app from .env. Uses --stage to avoid restarting
# before deploy. NEVER prints secret values.
set_secrets() {
    local app="$1"
    shift
    local keys=("$@")
    local args=()
    local missing=()

    for key in "${keys[@]}"; do
        local val
        val=$(read_env "$key")
        if [[ -z "$val" ]]; then
            missing+=("$key")
        else
            args+=("${key}=${val}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "    WARNING: Missing from .env: ${missing[*]}"
    fi

    if [[ ${#args[@]} -eq 0 ]]; then
        echo "    No secrets to set."
        return
    fi

    # Print key names only, never values
    echo "    Setting ${#args[@]} secret(s): ${keys[*]}"

    if $DRY_RUN; then
        echo "    [dry-run] fly secrets set --app $app --stage <${#args[@]} secrets>"
    else
        # Disable trace to prevent secrets leaking to logs
        set +x 2>/dev/null || true
        fly secrets set --app "$app" --stage "${args[@]}"
    fi
}

wait_healthy() {
    local app="$1"
    if $DRY_RUN; then
        echo "    [dry-run] wait for $app healthy"
        return
    fi
    echo "    Waiting for $app to be healthy..."
    fly status --app "$app" --watch 2>/dev/null || true
    # Give it a moment to stabilize
    sleep 3
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "Deploying personal-agent stack"
echo "  Log service:  $LOG_APP"
echo "  Cred proxy:   $PROXY_APP"
echo "  Agent:        $AGENT_APP"
$DRY_RUN && echo "  Mode: DRY RUN"
$SKIP_SECRETS && echo "  Skipping secrets"
echo ""

# 1. Set secrets
if ! $SKIP_SECRETS; then
    step "Setting secrets on $PROXY_APP"
    set_secrets "$PROXY_APP" "${CRED_PROXY_SECRETS[@]}"

    step "Setting secrets on $AGENT_APP"
    set_secrets "$AGENT_APP" "${AGENT_SECRETS[@]}"
    echo ""
fi

# 2. Deploy log service
step "Deploying $LOG_APP"
run fly deploy log-service/
wait_healthy "$LOG_APP"
echo ""

# 3. Deploy credential proxy
step "Deploying $PROXY_APP"
run fly deploy credential-proxy/
wait_healthy "$PROXY_APP"
echo ""

# 4. Deploy agent
step "Deploying $AGENT_APP"
run fly deploy --app "$AGENT_APP"
echo ""

# 5. Verify
step "Checking agent startup"
if ! $DRY_RUN; then
    fly logs --app "$AGENT_APP" --no-tail 2>/dev/null | tail -10 || true
fi

echo ""
echo "Deploy complete."
