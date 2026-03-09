#!/bin/sh
set -e

# Fly volumes mount as root. Fix ownership so appuser can write,
# then drop privileges via gosu.
_bootstrap() {
    # Ensure persistent workspace directory exists and seed bootstrap files
    # from the image if they aren't already on the volume.
    mkdir -p /data/nanobot/workspace
    if [ -d workspace ]; then
        for f in workspace/*; do
            dest="/data/nanobot/workspace/$(basename "$f")"
            if [ ! -e "$dest" ]; then
                cp "$f" "$dest"
                echo "[start.sh] Seeded $dest from image"
            fi
        done
    fi
}

if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /data
    _bootstrap
    exec gosu appuser .venv/bin/python -m personal_agent.main
else
    # Already running as non-root (e.g. local Docker with USER directive)
    mkdir -p /data/nanobot
    _bootstrap
    exec .venv/bin/python -m personal_agent.main
fi
