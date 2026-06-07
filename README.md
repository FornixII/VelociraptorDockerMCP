# Velociraptor MCP Server

A containerized [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes a [Velociraptor](https://docs.velociraptor.app) deployment to MCP-compatible
clients (Claude, IDE agents, etc.). It connects to Velociraptor's gRPC API over mutual
TLS and surfaces a general-purpose VQL tool, focused DFIR workflow tools, and built-in
EVTX analysis with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and
[Hayabusa](https://github.com/Yamato-Security/hayabusa).

## Tools

### Velociraptor (gRPC API)

| Tool | Purpose | Read-only |
|------|---------|-----------|
| `velociraptor_run_vql` | Run any VQL query (full API power) | No* |
| `velociraptor_list_clients` | Search enrolled endpoints by host/label | Yes |
| `velociraptor_get_client` | Full metadata for one client | Yes |
| `velociraptor_list_hunts` | List hunts, newest first | Yes |
| `velociraptor_create_hunt` | Create a fleet-wide hunt | No |
| `velociraptor_get_hunt_results` | Read rows collected by a hunt | Yes |
| `velociraptor_collect_artifact` | Collect artifact(s) from one client | No |
| `velociraptor_get_flow_results` | Read results of a completed collection | Yes |

### EVTX analysis (Chainsaw + Hayabusa)

| Tool | Purpose | Read-only |
|------|---------|-----------|
| `velociraptor_list_evtx_data` | List EVTX files available for analysis | Yes |
| `chainsaw_hunt` | Sigma hunt over EVTX, detections grouped by rule | Yes |
| `chainsaw_search` | Raw string/regex search across EVTX records | Yes |
| `hayabusa_timeline` | Sigma-based forensic timeline (JSON) | Yes |

\* VQL is usually read-only, but it can also perform actions, so the tool isn't
marked read-only.

### How the two halves connect

Velociraptor collects the Windows event logs; Chainsaw and Hayabusa analyze them.
The bundled rule sets (Chainsaw's Sigma + native rules, Hayabusa's Sigma rules) ship
inside the image, so no internet access is needed at analysis time.

```
                ┌────────────── Velociraptor server ──────────────┐
   endpoints ──▶│  collect_artifact / hunt  ──▶  .evtx files       │
                └───────────────────────────────────────┬─────────┘
                                                         │ (you copy EVTX out)
                                                         ▼
                                            EVTX_DATA_DIR (./data ▶ /data)
                                                         │
                       chainsaw_hunt / chainsaw_search / hayabusa_timeline
```

Drop collected `.evtx` files into `./data` (per-host subfolders recommended, e.g.
`./data/C.abc123/Security.evtx`), then point the analysis tools at those paths.
You can pull EVTX from an endpoint with `velociraptor_collect_artifact` using an
artifact like `Windows.EventLogs.Evtx`, then export the files to `./data`.

## 1. Generate an API config on your Velociraptor server

The container authenticates with an `api_client` config containing mTLS material.
Generate one on the Velociraptor server:

```bash
velociraptor --config /etc/velociraptor/server.config.yaml \
    config api_client --name mcp --role administrator \
    > ./config/api.config.yaml
```

Then add the API client's common name to the server's `API.access` allow-list (the
command prints a hint, or configure it in `server.config.yaml`). Use the least
privileged role that meets your needs (e.g. `reader` if you only need queries).

Place the generated file at `./config/api.config.yaml` next to `docker-compose.yml`.
It contains a **private key** — keep it out of source control (already gitignored).

The config's `api_connection_string` must be reachable from the container. If
Velociraptor runs on the Docker host, use the host's IP (or `host.docker.internal`
on Docker Desktop) rather than `127.0.0.1`.

## 2. Build and run

```bash
docker compose up --build -d
```

This starts the server on `http://localhost:8000` using the streamable-HTTP MCP
transport. Check logs with `docker compose logs -f`.

## 3. Connect a client

### Streamable HTTP (default for the container)

Point your MCP client at `http://localhost:8000/mcp`.

### stdio (local, no long-running container)

Some clients launch the server as a subprocess. Run with stdio instead:

```jsonc
{
  "mcpServers": {
    "velociraptor": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "MCP_TRANSPORT=stdio",
        "-v", "/abs/path/to/config/api.config.yaml:/config/api.config.yaml:ro",
        "velociraptor-mcp:latest"
      ]
    }
  }
}
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `VELOCIRAPTOR_API_CONFIG` | `/config/api.config.yaml` | Path to the mounted api_client config |
| `VELOCIRAPTOR_ORG_ID` | `""` | Default org to target (`""` = root) |
| `MCP_TRANSPORT` | `http` (image) / `stdio` (code default) | `http` or `stdio` |
| `MCP_HOST` | `0.0.0.0` | Bind host (http only) |
| `MCP_PORT` | `8000` | Bind port (http only) |
| `EVTX_DATA_DIR` | `/data` | Directory of EVTX files for Chainsaw/Hayabusa |
| `CHAINSAW_SIGMA_DIR` | `/opt/chainsaw/sigma` | Sigma rules for Chainsaw |
| `CHAINSAW_RULES_DIR` | `/opt/chainsaw/rules` | Chainsaw native rules |
| `CHAINSAW_MAPPING` | `/opt/chainsaw/mappings/sigma-event-logs-all.yml` | Sigma field mapping |
| `HAYABUSA_RULES_DIR` | `/opt/hayabusa/rules` | Hayabusa Sigma rules |

Tool versions are pinned in the Dockerfile via build args (`CHAINSAW_VERSION`,
`HAYABUSA_VERSION`) — currently Chainsaw v2.14.1 and Hayabusa v3.8.1. Override at
build time: `docker compose build --build-arg HAYABUSA_VERSION=3.8.1`.

## Example prompts once connected

- "List all Windows hosts seen in the last day."
- "Collect `Windows.System.Pslist` from `C.abc123` and show me the results."
- "Start a hunt collecting `Generic.Client.Info` across the fleet."
- "Run VQL: `SELECT * FROM info()`."
- "What EVTX files do we have to analyze?" (`velociraptor_list_evtx_data`)
- "Run a Chainsaw hunt on `C.abc123/Security.evtx` and show critical hits."
- "Search the collected logs for 'mimikatz'."
- "Build a Hayabusa timeline from `C.abc123` at medium severity and up."

## Security notes

- The api_client config grants API access at the role you chose — treat it like a
  credential. Mount it read-only (the compose file does).
- Prefer a narrowly scoped role over `administrator` where possible.
- The HTTP transport has no built-in auth; bind it to localhost or place it behind
  a reverse proxy / network policy if exposed beyond the host.
- The server runs as a non-root user inside the container.

## Local development (without Docker)

```bash
pip install -r requirements.txt
export VELOCIRAPTOR_API_CONFIG=./config/api.config.yaml
export MCP_TRANSPORT=stdio
python server.py
```

The Velociraptor tools work as long as `pyvelociraptor` is installed. The
`chainsaw_*` and `hayabusa_*` tools additionally require the `chainsaw` and
`hayabusa` binaries on your `PATH` (the Docker image installs them for you). If a
binary is missing, only those tools error — the rest keep working.
