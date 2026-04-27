FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# System deps: Chromium (browser automation), Node.js + npm (agent-browser, docx, pptxgenjs),
# LibreOffice (formula recalc, PDF/image conversion), Poppler (pdftoppm, pdftotext),
# qpdf (PDF manipulation), Tesseract (OCR)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation fonts-noto-cjk fonts-noto-color-emoji \
    nodejs npm \
    libreoffice-calc libreoffice-writer libreoffice-impress \
    poppler-utils \
    qpdf \
    tesseract-ocr \
    git \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pandoc + hledger — standalone binaries avoid pulling in the full Haskell runtime
RUN curl -sL https://github.com/jgm/pandoc/releases/download/3.6.4/pandoc-3.6.4-linux-amd64.tar.gz \
    | tar xz --strip-components=1 -C /usr/local \
    && curl -sL https://github.com/simonmichael/hledger/releases/download/1.42/hledger-linux-x64.tar.gz \
    | tar xz -C /usr/local/bin hledger

# Install agent-browser CLI and skill npm deps
RUN npm install -g agent-browser pptxgenjs docx && npm cache clean --force

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
# Git identity for the agent (used when committing to /workspace journals)
RUN git config --system user.name "Polynumeral Agent" && \
    git config --system user.email "agent@polynumeral.com" && \
    git config --system --add safe.directory /workspace

USER appuser

CMD ["./start.sh"]
