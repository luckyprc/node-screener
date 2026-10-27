FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 curl ca-certificates gzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Mihomo v1.19.33 (verified 2026-10-27 via GitHub releases API)
RUN curl -L -o /tmp/mihomo.gz https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz \
    && gunzip /tmp/mihomo.gz \
    && mv /tmp/mihomo-linux-amd64-v1.19.33 /usr/local/bin/mihomo \
    && chmod +x /usr/local/bin/mihomo
COPY screener.py server.py /app/
RUN mkdir -p /app/data
ENV DATA_DIR=/app/data
# Render injects PORT automatically; default 10000 for local runs
ENV PORT=10000
CMD ["python3", "server.py"]
