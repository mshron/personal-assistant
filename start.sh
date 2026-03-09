#!/bin/sh
set -e

# Fly volumes mount as root. Fix ownership so appuser can write,
# then drop privileges via gosu.
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /data
    exec gosu appuser .venv/bin/python -m personal_agent.main
else
    # Already running as non-root (e.g. local Docker with USER directive)
    mkdir -p /data/nanobot
    exec .venv/bin/python -m personal_agent.main
fi
