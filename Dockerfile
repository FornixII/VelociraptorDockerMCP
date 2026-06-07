# Velociraptor MCP server — with Chainsaw + Hayabusa EVTX analysis tools
#
# Build args let you pin tool versions:
#   docker build --build-arg CHAINSAW_VERSION=v2.14.1 --build-arg HAYABUSA_VERSION=3.8.1 .

# ---------------------------------------------------------------------------
# Stage 1: download Chainsaw + Hayabusa release binaries and their rule sets.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS tools

ARG CHAINSAW_VERSION=v2.14.1
ARG HAYABUSA_VERSION=3.8.1
ARG TARGETARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tar unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# --- Chainsaw: all-in-one bundle (binary + chainsaw rules + Sigma rules + mappings)
RUN curl -fsSL -o /tmp/chainsaw.tar.gz \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/${CHAINSAW_VERSION}/chainsaw_all_platforms+rules+examples.tar.gz" \
    && tar -xzf /tmp/chainsaw.tar.gz -C /opt \
    && rm /tmp/chainsaw.tar.gz \
    # Normalize: ensure the linux binary is at a stable path and on PATH.
    && BIN="$(find /opt/chainsaw -maxdepth 1 -name 'chainsaw_x86_64-unknown-linux-gnu*' | head -1)" \
    && install -m 0755 "$BIN" /usr/local/bin/chainsaw \
    && /usr/local/bin/chainsaw --version

# --- Hayabusa: linux x64 build, then refresh the Sigma rule set.
RUN curl -fsSL -o /tmp/hayabusa.zip \
      "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
    && mkdir -p /opt/hayabusa \
    && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
    && rm /tmp/hayabusa.zip \
    && BIN="$(find /opt/hayabusa -maxdepth 1 -name 'hayabusa-*-lin-x64-gnu' | head -1)" \
    && install -m 0755 "$BIN" /usr/local/bin/hayabusa \
    && /usr/local/bin/hayabusa update-rules -q || true \
    && /usr/local/bin/hayabusa help >/dev/null

# ---------------------------------------------------------------------------
# Stage 2: runtime image.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# grpcio ships wheels; build-essential is a safety net for source builds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bring in the analysis binaries and their rule sets from the tools stage.
COPY --from=tools /usr/local/bin/chainsaw /usr/local/bin/chainsaw
COPY --from=tools /usr/local/bin/hayabusa /usr/local/bin/hayabusa
COPY --from=tools /opt/chainsaw /opt/chainsaw
COPY --from=tools /opt/hayabusa /opt/hayabusa

COPY server.py .

# Non-root runtime user.
RUN useradd --create-home --uid 10001 mcp \
    && mkdir -p /config /data \
    && chown -R mcp:mcp /app /config /data
USER mcp

ENV VELOCIRAPTOR_API_CONFIG=/config/api.config.yaml \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    EVTX_DATA_DIR=/data \
    CHAINSAW_BIN=chainsaw \
    CHAINSAW_SIGMA_DIR=/opt/chainsaw/sigma \
    CHAINSAW_RULES_DIR=/opt/chainsaw/rules \
    CHAINSAW_MAPPING=/opt/chainsaw/mappings/sigma-event-logs-all.yml \
    HAYABUSA_BIN=hayabusa \
    HAYABUSA_RULES_DIR=/opt/hayabusa/rules

EXPOSE 8000

CMD ["python", "server.py"]
