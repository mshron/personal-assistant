#!/bin/sh
set -e

# On Fly.io: runs as root, volumes mount as root.
# Fix ownership and drop to appuser via gosu.
#
# On local Docker: runs as root (no USER directive), but volumes
# are initialized from the image with correct appuser ownership.
# chown may fail due to cap_drop:ALL — that's fine, skip it.

if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /data 2>/dev/null || true
    exec gosu appuser python main.py
else
    exec python main.py
fi
