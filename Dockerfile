# Velociraptor MCP server
FROM python:3.12-slim

# grpcio wheels are prebuilt; build-essential is a safety net for source builds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Run as non-root.
RUN useradd --create-home --uid 10001 mcp \
    && mkdir -p /config \
    && chown -R mcp:mcp /app /config
USER mcp

# api_client config is mounted here at runtime (read-only).
ENV VELOCIRAPTOR_API_CONFIG=/config/api.config.yaml \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

EXPOSE 8000

CMD ["python", "server.py"]
