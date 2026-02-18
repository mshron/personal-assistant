#!/bin/sh
# Process runner for Fly.io single-machine deployment.
# Starts tokenizer, log-service, and agent. If any exits, all stop.

set -e

# Ensure data directories exist
mkdir -p /data/nanobot /data/logs

# Start tokenizer in background
tokenizer &
TOKENIZER_PID=$!

# Start log service in background
LOG_FILE=/data/logs/agent.jsonl python log-service/main.py &
LOG_PID=$!

# Give services a moment to bind
sleep 1

# Start agent in foreground
exec uv run python -m personal_agent.main
