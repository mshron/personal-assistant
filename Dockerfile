FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies (no dev deps)
RUN uv sync --no-dev --frozen

# Copy application code
COPY personal_agent/ personal_agent/
COPY nanobot-config.json .

# Run as non-root for defense-in-depth.
# Create appuser and ensure /data is writable (volume mount target).
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/sh appuser && \
    mkdir -p /data/nanobot && chown -R appuser:appuser /data
USER appuser

CMD [".venv/bin/python", "-m", "personal_agent.main"]
