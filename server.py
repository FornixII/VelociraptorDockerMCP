#!/usr/bin/env python3
"""
MCP Server for Velociraptor (DFIR endpoint visibility & hunting platform).

This server exposes the Velociraptor gRPC API to MCP clients. Velociraptor's API
is intentionally VQL-centric: almost every capability (querying endpoints, running
hunts, searching clients, collecting artifacts) is expressed as a VQL query streamed
over a single gRPC `Query` endpoint. This server provides:

  * A general-purpose `velociraptor_run_vql` tool (full power), and
  * Focused workflow tools for the most common DFIR tasks (clients, hunts, collections)
    that build safe, parameterized VQL under the hood.

Connection uses mutual TLS via an api_client config generated on the Velociraptor
server with:

    velociraptor --config server.config.yaml config api_client \
        --name mcp --role administrator > api.config.yaml

Configuration (environment variables):
  VELOCIRAPTOR_API_CONFIG  Path to the api_client config yaml (default: /config/api.config.yaml)
  VELOCIRAPTOR_ORG_ID      Default org ID to target (default: "" = root org)
  MCP_TRANSPORT            "stdio" (default) or "http" (streamable HTTP)
  MCP_HOST                 Bind host for http transport (default: 0.0.0.0)
  MCP_PORT                 Bind port for http transport (default: 8000)
"""

import asyncio
import json
import os
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Constants & configuration
# ---------------------------------------------------------------------------

mcp = FastMCP("velociraptor_mcp")

CONFIG_PATH = os.environ.get("VELOCIRAPTOR_API_CONFIG", "/config/api.config.yaml")
DEFAULT_ORG_ID = os.environ.get("VELOCIRAPTOR_ORG_ID", "")

# Self-signed Velociraptor server certs are issued to this common name. The gRPC
# client must override the target name to validate the cert when connecting by IP.
_SSL_TARGET_NAME_OVERRIDE = "VelociraptorServer"

# Lazily-loaded config dict (ca_certificate, client_cert, client_private_key,
# api_connection_string). Loaded once and reused across tool calls.
_CONFIG: Optional[Dict[str, Any]] = None


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


# ---------------------------------------------------------------------------
# Core gRPC / VQL engine (shared by every tool)
# ---------------------------------------------------------------------------


def _load_config() -> Dict[str, Any]:
    """Load and cache the Velociraptor api_client config from disk.

    Returns:
        dict: Parsed config containing the mTLS material and connection string.

    Raises:
        FileNotFoundError: If the config file does not exist at CONFIG_PATH.
    """
    global _CONFIG
    if _CONFIG is None:
        if not os.path.exists(CONFIG_PATH):
            raise FileNotFoundError(
                f"Velociraptor api_client config not found at '{CONFIG_PATH}'. "
                "Generate one on the server with: velociraptor --config "
                "server.config.yaml config api_client --name mcp --role "
                "administrator > api.config.yaml, then mount it into the "
                "container and set VELOCIRAPTOR_API_CONFIG."
            )
        _CONFIG = pyvelociraptor.LoadConfigFile(CONFIG_PATH)
    return _CONFIG


def _run_vql_blocking(
    query: str,
    env_dict: Optional[Dict[str, Any]],
    org_id: Optional[str],
    timeout: int,
    max_rows: int,
) -> Dict[str, Any]:
    """Execute a VQL query over gRPC and collect rows + logs (blocking).

    This runs synchronously (grpc's Python streaming API is blocking) and is
    designed to be invoked via asyncio.to_thread from async tools. It is bounded:
    it stops once ``max_rows`` rows have been collected, which makes it safe to
    call even against streaming/event VQL plugins.

    Args:
        query: The VQL query string to execute.
        env_dict: Optional environment bindings made available to the query as
            VQL variables (e.g. {"search_term": "host:web*"}). Values are passed
            as strings; reference them by name inside the VQL to avoid injection.
        org_id: Velociraptor org ID to target ("" for the root org).
        timeout: Server-side query timeout in seconds (0 = server default).
        max_rows: Maximum number of result rows to collect before returning.

    Returns:
        dict with keys:
            rows (List[dict]): Collected result rows (capped at max_rows).
            logs (List[str]): Human-readable query execution log lines.
            truncated (bool): True if the row cap was hit and more may exist.
    """
    config = _load_config()

    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    options = (("grpc.ssl_target_name_override", _SSL_TARGET_NAME_OVERRIDE),)

    env = [{"key": k, "value": str(v)} for k, v in (env_dict or {}).items()]

    rows: List[Dict[str, Any]] = []
    logs: List[str] = []
    truncated = False

    with grpc.secure_channel(
        config["api_connection_string"], creds, options
    ) as channel:
        stub = api_pb2_grpc.APIStub(channel)
        request = api_pb2.VQLCollectorArgs(
            org_id=org_id if org_id is not None else DEFAULT_ORG_ID,
            max_wait=1,
            max_row=min(max_rows, 1000),
            timeout=timeout,
            Query=[api_pb2.VQLRequest(Name="MCPQuery", VQL=query)],
            env=env,
        )

        for response in stub.Query(request):
            if response.Response:
                batch = json.loads(response.Response)
                for row in batch:
                    rows.append(row)
                    if len(rows) >= max_rows:
                        truncated = True
                        break
                if truncated:
                    break
            elif response.log:
                logs.append(
                    "%s: %s"
                    % (time.ctime(response.timestamp / 1000000), response.log)
                )

    return {"rows": rows, "logs": logs, "truncated": truncated}


async def _run_vql(
    query: str,
    env_dict: Optional[Dict[str, Any]] = None,
    org_id: Optional[str] = None,
    timeout: int = 60,
    max_rows: int = 200,
) -> Dict[str, Any]:
    """Async wrapper around the blocking gRPC VQL runner."""
    return await asyncio.to_thread(
        _run_vql_blocking, query, env_dict, org_id, timeout, max_rows
    )


def _handle_error(e: Exception) -> str:
    """Format exceptions into actionable, agent-friendly error strings."""
    if isinstance(e, FileNotFoundError):
        return f"Error: {e}"
    if isinstance(e, grpc.RpcError):
        code = e.code() if hasattr(e, "code") else None
        detail = e.details() if hasattr(e, "details") else str(e)
        if code == grpc.StatusCode.UNAVAILABLE:
            return (
                "Error: Could not reach the Velociraptor server. Check that "
                "api_connection_string in the config is correct and the server "
                f"is reachable from the container. Detail: {detail}"
            )
        if code == grpc.StatusCode.UNAUTHENTICATED:
            return (
                "Error: Authentication failed. The api_client certificate may be "
                "invalid, expired, or lack the required role. Detail: " + str(detail)
            )
        if code == grpc.StatusCode.PERMISSION_DENIED:
            return (
                "Error: Permission denied. The API user's role does not allow this "
                f"operation. Detail: {detail}"
            )
        return f"Error: Velociraptor gRPC call failed ({code}): {detail}"
    return f"Error: Unexpected {type(e).__name__}: {e}"


def _format_rows(
    rows: List[Dict[str, Any]],
    logs: List[str],
    truncated: bool,
    fmt: ResponseFormat,
    title: str,
) -> str:
    """Render query results as either JSON or readable markdown."""
    if fmt == ResponseFormat.JSON:
        return json.dumps(
            {
                "count": len(rows),
                "truncated": truncated,
                "rows": rows,
                "logs": logs,
            },
            indent=2,
            default=str,
        )

    lines = [f"# {title}", "", f"Returned {len(rows)} row(s)" + (
        " (truncated — increase max_rows for more)" if truncated else ""
    ), ""]
    if not rows:
        lines.append("_No results._")
    for i, row in enumerate(rows, 1):
        lines.append(f"## Row {i}")
        for k, v in row.items():
            if isinstance(v, (dict, list)):
                v = json.dumps(v, default=str)
            lines.append(f"- **{k}**: {v}")
        lines.append("")
    if logs:
        lines.append("### Query logs")
        lines.extend(f"- {ln}" for ln in logs)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pydantic input models
# ---------------------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )


class RunVqlInput(_Base):
    """Input for running an arbitrary VQL query."""

    vql: str = Field(
        ...,
        description="The VQL query to execute (e.g. \"SELECT * FROM info()\").",
        min_length=1,
        max_length=20000,
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional VQL environment bindings, exposed as variables in "
        "the query. Prefer these over string interpolation to avoid injection "
        "(e.g. {\"host\": \"web01\"} then reference `host` in the VQL).",
    )
    org_id: Optional[str] = Field(
        default=None,
        description="Org ID to target. Omit for the default/root org.",
        max_length=128,
    )
    timeout: int = Field(
        default=60,
        description="Server-side query timeout in seconds (0 = server default).",
        ge=0,
        le=3600,
    )
    max_rows: int = Field(
        default=200,
        description="Max rows to collect before returning. Bounds streaming queries.",
        ge=1,
        le=1000,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' for human-readable, 'json' for machine-readable.",
    )

    @field_validator("vql")
    @classmethod
    def _no_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("VQL query cannot be empty.")
        return v


class ListClientsInput(_Base):
    """Input for searching/listing Velociraptor clients (endpoints)."""

    search: str = Field(
        default="all",
        description="Search term. Examples: 'all', 'host:web*', 'label:production', "
        "'mac:00-11-...', or a hostname substring. Velociraptor client index syntax.",
        max_length=256,
    )
    limit: int = Field(
        default=50, description="Max clients to return.", ge=1, le=1000
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class GetClientInput(_Base):
    """Input for fetching details about a single client."""

    client_id: str = Field(
        ...,
        description="The Velociraptor client ID (e.g. 'C.1234567890abcdef').",
        min_length=2,
        max_length=128,
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class ListHuntsInput(_Base):
    """Input for listing hunts."""

    limit: int = Field(default=50, description="Max hunts to return.", ge=1, le=500)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class CreateHuntInput(_Base):
    """Input for creating a new hunt."""

    artifacts: List[str] = Field(
        ...,
        description="Artifact names to collect across the fleet "
        "(e.g. ['Windows.System.Pslist', 'Generic.Client.Info']).",
        min_length=1,
        max_length=50,
    )
    description: str = Field(
        ...,
        description="Human-readable description of the hunt's purpose.",
        min_length=1,
        max_length=500,
    )
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Artifact parameters as key/value pairs applied to the collection.",
    )
    org_id: Optional[str] = Field(default=None, max_length=128)


class HuntResultsInput(_Base):
    """Input for fetching results collected by a hunt."""

    hunt_id: str = Field(
        ...,
        description="The hunt ID (e.g. 'H.1234abcd').",
        min_length=2,
        max_length=128,
    )
    artifact: str = Field(
        ...,
        description="Which artifact's results to fetch (must be one the hunt collected).",
        min_length=1,
        max_length=256,
    )
    limit: int = Field(default=100, description="Max rows to return.", ge=1, le=1000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class CollectArtifactInput(_Base):
    """Input for collecting artifact(s) from a single client."""

    client_id: str = Field(
        ...,
        description="Target client ID (e.g. 'C.1234567890abcdef').",
        min_length=2,
        max_length=128,
    )
    artifacts: List[str] = Field(
        ...,
        description="Artifact names to collect (e.g. ['Windows.System.Pslist']).",
        min_length=1,
        max_length=50,
    )
    env: Optional[Dict[str, str]] = Field(
        default=None, description="Artifact parameters as key/value pairs."
    )
    org_id: Optional[str] = Field(default=None, max_length=128)


class FlowResultsInput(_Base):
    """Input for fetching results from a completed collection (flow)."""

    client_id: str = Field(
        ..., description="Client ID the flow ran on.", min_length=2, max_length=128
    )
    flow_id: str = Field(
        ...,
        description="The flow ID returned by velociraptor_collect_artifact (e.g. 'F.ABC123').",
        min_length=2,
        max_length=128,
    )
    artifact: str = Field(
        ...,
        description="Which collected artifact's results to read.",
        min_length=1,
        max_length=256,
    )
    limit: int = Field(default=100, description="Max rows to return.", ge=1, le=1000)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="velociraptor_run_vql",
    annotations={
        "title": "Run VQL Query",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def velociraptor_run_vql(params: RunVqlInput) -> str:
    """Execute an arbitrary VQL (Velociraptor Query Language) query on the server.

    This is the most flexible tool — it can do anything the Velociraptor API user
    is permitted to do, since clients, hunts, flows, and server state are all
    exposed through VQL plugins. Use the focused tools (list_clients, create_hunt,
    etc.) for common tasks; use this when you need something they don't cover.

    Note: most VQL is read-only, but VQL can also perform actions (creating hunts,
    starting collections, modifying labels), so this tool is not marked read-only.

    Args:
        params (RunVqlInput):
            - vql (str): The VQL query (e.g. "SELECT * FROM info()").
            - env (dict, optional): Variable bindings referenced inside the VQL.
            - org_id (str, optional): Org to target.
            - timeout (int): Server-side timeout in seconds (default 60).
            - max_rows (int): Row cap, bounds streaming queries (default 200).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Results rendered as markdown or JSON. JSON schema:
            {"count": int, "truncated": bool, "rows": [ {col: value, ...} ], "logs": [str]}
        On failure: "Error: <actionable message>".

    Examples:
        - "What server is this?" -> vql="SELECT * FROM info()"
        - "List artifacts mentioning prefetch" ->
          vql="SELECT name FROM artifact_definitions() WHERE name =~ 'Prefetch'"
    """
    try:
        result = await _run_vql(
            params.vql,
            env_dict=params.env,
            org_id=params.org_id,
            timeout=params.timeout,
            max_rows=params.max_rows,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            "VQL Results",
        )
    except Exception as e:  # noqa: BLE001 - normalized into actionable text
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_list_clients",
    annotations={
        "title": "Search Clients",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def velociraptor_list_clients(params: ListClientsInput) -> str:
    """Search the Velociraptor client index for endpoints (hosts).

    Uses the VQL `clients()` plugin to find enrolled endpoints by hostname, label,
    or other index terms. Returns identifying info you can feed into collection or
    hunt tools.

    Args:
        params (ListClientsInput):
            - search (str): Index search term ('all', 'host:web*', 'label:prod', ...).
            - limit (int): Max clients to return (default 50).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Rows with client_id, os_info.hostname, os_info.system, last_seen_at,
        labels, last_ip. On failure: "Error: <message>".

    Examples:
        - "Find all Windows web servers" -> search="host:web*"
        - "Which hosts have the 'quarantine' label?" -> search="label:quarantine"
    """
    try:
        vql = (
            "SELECT client_id, os_info.hostname AS hostname, "
            "os_info.system AS os, last_seen_at, labels, last_ip "
            "FROM clients(search=search) LIMIT atoi(string=row_limit)"
        )
        result = await _run_vql(
            vql,
            env_dict={"search": params.search, "row_limit": str(params.limit)},
            max_rows=params.limit,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            f"Clients matching '{params.search}'",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_get_client",
    annotations={
        "title": "Get Client Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def velociraptor_get_client(params: GetClientInput) -> str:
    """Fetch full metadata for a single client by its client ID.

    Args:
        params (GetClientInput):
            - client_id (str): The 'C.xxxx' client identifier.
            - response_format: 'markdown' or 'json'.

    Returns:
        str: A single row of client metadata (OS, hostname, agent version, labels,
        first/last seen). On failure: "Error: <message>".
    """
    try:
        vql = "SELECT * FROM clients(client_id=client_id)"
        result = await _run_vql(
            vql, env_dict={"client_id": params.client_id}, max_rows=1
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            f"Client {params.client_id}",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_list_hunts",
    annotations={
        "title": "List Hunts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def velociraptor_list_hunts(params: ListHuntsInput) -> str:
    """List hunts on the server, newest first.

    Args:
        params (ListHuntsInput):
            - limit (int): Max hunts to return (default 50).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Rows with hunt_id, state, description, create_time, start_time,
        total scheduled/completed clients, and the artifacts collected.
        On failure: "Error: <message>".
    """
    try:
        vql = (
            "SELECT hunt_id, state, hunt_description AS description, create_time, "
            "start_time, stats.total_clients_scheduled AS scheduled, "
            "stats.total_clients_with_results AS with_results, "
            "start_request.artifacts AS artifacts "
            "FROM hunts() ORDER BY create_time DESC"
        )
        result = await _run_vql(vql, max_rows=params.limit)
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            "Hunts",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_create_hunt",
    annotations={
        "title": "Create Hunt",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def velociraptor_create_hunt(params: CreateHuntInput) -> str:
    """Create a new hunt to collect artifact(s) across the fleet.

    A hunt schedules a collection against all matching clients. This creates the
    hunt in a paused state by default behavior of the `hunt()` VQL function; review
    and start it in the Velociraptor UI (or via VQL) once verified.

    Args:
        params (CreateHuntInput):
            - artifacts (List[str]): Artifact names to collect.
            - description (str): Purpose of the hunt.
            - env (dict, optional): Artifact parameters.
            - org_id (str, optional): Org to target.

    Returns:
        str: JSON of the created hunt including its hunt_id. On failure: "Error: <message>".

    Examples:
        - "Hunt for running processes everywhere" ->
          artifacts=["Windows.System.Pslist"], description="IR triage process list"
    """
    try:
        # FastMCP env bindings carry strings only; list/dict artifact args are
        # passed as JSON and parsed inside VQL so names/params are never string-spliced.
        vql_structured = (
            "LET artifacts <= parse_json_array(data=artifacts_json) "
            "LET env <= parse_json(data=env_json) "
            "SELECT hunt(description=description, artifacts=artifacts, "
            "spec=dict(artifacts=env)) AS hunt FROM scope()"
        )
        result = await _run_vql(
            vql_structured,
            env_dict={
                "description": params.description,
                "artifacts_json": json.dumps(params.artifacts),
                "env_json": json.dumps(params.env or {}),
            },
            org_id=params.org_id,
            max_rows=1,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            ResponseFormat.JSON,
            "Created Hunt",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_get_hunt_results",
    annotations={
        "title": "Get Hunt Results",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def velociraptor_get_hunt_results(params: HuntResultsInput) -> str:
    """Fetch rows collected by a hunt for a specific artifact.

    Args:
        params (HuntResultsInput):
            - hunt_id (str): The 'H.xxxx' hunt identifier.
            - artifact (str): Artifact whose results to read.
            - limit (int): Max rows (default 100).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Collected rows (one per matching record across all hosts in the hunt).
        On failure: "Error: <message>".
    """
    try:
        vql = (
            "SELECT * FROM hunt_results(hunt_id=hunt_id, artifact=artifact) "
            "LIMIT atoi(string=row_limit)"
        )
        result = await _run_vql(
            vql,
            env_dict={
                "hunt_id": params.hunt_id,
                "artifact": params.artifact,
                "row_limit": str(params.limit),
            },
            max_rows=params.limit,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            f"Hunt {params.hunt_id} results ({params.artifact})",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_collect_artifact",
    annotations={
        "title": "Collect Artifact From Client",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def velociraptor_collect_artifact(params: CollectArtifactInput) -> str:
    """Schedule a collection of artifact(s) on a single client and return the flow ID.

    This kicks off an asynchronous collection (a "flow") on the target endpoint.
    The agent must be online to respond. Use the returned flow_id with
    velociraptor_get_flow_results once the flow completes.

    Args:
        params (CollectArtifactInput):
            - client_id (str): Target client.
            - artifacts (List[str]): Artifact names to collect.
            - env (dict, optional): Artifact parameters.
            - org_id (str, optional): Org to target.

    Returns:
        str: JSON including flow_id and request details. On failure: "Error: <message>".

    Examples:
        - "Grab the process list from C.abc123" ->
          client_id="C.abc123", artifacts=["Windows.System.Pslist"]
    """
    try:
        vql = (
            "LET artifacts <= parse_json_array(data=artifacts_json) "
            "LET env <= parse_json(data=env_json) "
            "SELECT collect_client(client_id=client_id, artifacts=artifacts, "
            "spec=dict(artifacts=env)) AS flow FROM scope()"
        )
        result = await _run_vql(
            vql,
            env_dict={
                "client_id": params.client_id,
                "artifacts_json": json.dumps(params.artifacts),
                "env_json": json.dumps(params.env or {}),
            },
            org_id=params.org_id,
            max_rows=1,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            ResponseFormat.JSON,
            f"Collection scheduled on {params.client_id}",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


@mcp.tool(
    name="velociraptor_get_flow_results",
    annotations={
        "title": "Get Flow Results",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def velociraptor_get_flow_results(params: FlowResultsInput) -> str:
    """Read the results of a completed collection (flow) on a client.

    Args:
        params (FlowResultsInput):
            - client_id (str): Client the flow ran on.
            - flow_id (str): The 'F.xxxx' flow ID from velociraptor_collect_artifact.
            - artifact (str): Which collected artifact to read.
            - limit (int): Max rows (default 100).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Collected rows for that artifact. If empty, the flow may still be
        running or collected no data. On failure: "Error: <message>".
    """
    try:
        vql = (
            "SELECT * FROM source(client_id=client_id, flow_id=flow_id, "
            "artifact=artifact) LIMIT atoi(string=row_limit)"
        )
        result = await _run_vql(
            vql,
            env_dict={
                "client_id": params.client_id,
                "flow_id": params.flow_id,
                "artifact": params.artifact,
                "row_limit": str(params.limit),
            },
            max_rows=params.limit,
        )
        return _format_rows(
            result["rows"],
            result["logs"],
            result["truncated"],
            params.response_format,
            f"Flow {params.flow_id} results ({params.artifact})",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_error(e)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport in ("http", "streamable_http", "streamable-http"):
        mcp.settings.host = os.environ.get("MCP_HOST", "0.0.0.0")
        mcp.settings.port = int(os.environ.get("MCP_PORT", "8000"))
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
