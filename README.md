# Velociraptor MCP Server

A containerized [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes a [Velociraptor](https://docs.velociraptor.app) deployment to MCP-compatible
clients (Claude, IDE agents, etc.). It connects to Velociraptor's gRPC API over mutual
TLS and surfaces both a general-purpose VQL tool and focused DFIR workflow tools.

## Tools

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

\* VQL is usually read-only, but it can also perform actions, so the tool isn't
marked read-only.

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

## Example prompts once connected

- "List all Windows hosts seen in the last day."
- "Collect `Windows.System.Pslist` from `C.abc123` and show me the results."
- "Start a hunt collecting `Generic.Client.Info` across the fleet."
- "Run VQL: `SELECT * FROM info()`."

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
