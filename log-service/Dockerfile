FROM python:3.12-slim
WORKDIR /app
COPY main.py start.sh ./
RUN chmod +x start.sh

# Create non-root user for defense-in-depth.
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/sh appuser && \
    mkdir -p /data/logs && chown -R appuser:appuser /data

EXPOSE 8081
CMD ["./start.sh"]
