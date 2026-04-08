FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# System deps: Chromium + deps (browser automation), Node.js + npm (agent-browser)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation fonts-noto-cjk fonts-noto-color-emoji \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install agent-browser CLI (Rust binary distributed via npm)
RUN npm install -g agent-browser && npm cache clean --force

# Point agent-browser at system Chromium
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_DATA_DIR=/tmp/agent-browser
ENV AGENT_BROWSER_SOCKET_DIR=/tmp
ENV AGENT_BROWSER_CONTENT_BOUNDARIES=1

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies (no dev deps)
RUN uv sync --no-dev --frozen

# Copy application code
COPY personal_agent/ personal_agent/
COPY nanobot-config.json .
COPY workspace/ workspace/
COPY start.sh .
RUN chmod +x start.sh

# Run as non-root for defense-in-depth.
# Create appuser and ensure /data is writable (volume mount target).
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/sh appuser && \
    mkdir -p /data/nanobot && chown -R appuser:appuser /data
USER appuser

CMD ["./start.sh"]
