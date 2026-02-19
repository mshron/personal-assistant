#!/bin/sh
# Process runner for Fly.io single-machine deployment.
# Starts log-service and agent. If any exits, all stop.

set -e

# Ensure data directories exist
mkdir -p /data/nanobot /data/logs

# Start log service in background
LOG_FILE=/data/logs/agent.jsonl python log-service/main.py &
LOG_PID=$!

# Give log service a moment to bind
sleep 1

# Start agent in foreground
exec uv run python -m personal_agent.main
