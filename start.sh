#!/bin/sh
set -e
mkdir -p /data/nanobot
exec uv run python -m personal_agent.main
