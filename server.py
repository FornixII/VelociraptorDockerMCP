#!/usr/bin/env python3
"""
MCP Server for Velociraptor (DFIR endpoint visibility & hunting platform).

This server exposes the Velociraptor gRPC API to MCP clients. Velociraptor's API
is intentionally VQL-centric: almost every capability (querying endpoints, running
hunts, searching clients, collecting artifacts) is expressed as a VQL query streamed
over a single gRPC `Query` endpoint. This server provides:

  * A general-purpose `velociraptor_run_vql` tool (full power),
  * Focused workflow tools for the most common DFIR tasks (clients, hunts, collections)
    that build safe, parameterized VQL under the hood, and
  * EVTX analysis tools that run Chainsaw and Hayabusa (Sigma-based Windows event
    log hunters) over logs collected from endpoints. The typical workflow is:
    collect EVTX with Velociraptor -> write them to the shared data dir ->
    triage them with chainsaw_hunt / hayabusa_timeline.

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

EVTX analysis (Chainsaw / Hayabusa) configuration:
  EVTX_DATA_DIR            Directory holding EVTX files to analyze (default: /data)
  CHAINSAW_BIN             chainsaw binary (default: chainsaw, resolved on PATH)
  CHAINSAW_SIGMA_DIR       Sigma rule directory for chainsaw (default: /opt/chainsaw/sigma)
  CHAINSAW_RULES_DIR       Chainsaw native rule directory (default: /opt/chainsaw/rules)
  CHAINSAW_MAPPING         Chainsaw Sigma mapping file
                           (default: /opt/chainsaw/mappings/sigma-event-logs-all.yml)
  HAYABUSA_BIN             hayabusa binary (default: hayabusa, resolved on PATH)
  HAYABUSA_RULES_DIR       Hayabusa rule directory (default: /opt/hayabusa/rules)
"""

import asyncio
import json
import os
import tempfile
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


# EVTX analysis tool configuration (Chainsaw / Hayabusa run as subprocesses).
EVTX_DATA_DIR = os.environ.get("EVTX_DATA_DIR", "/data")
CHAINSAW_BIN = os.environ.get("CHAINSAW_BIN", "chainsaw")
CHAINSAW_SIGMA_DIR = os.environ.get("CHAINSAW_SIGMA_DIR", "/opt/chainsaw/sigma")
CHAINSAW_RULES_DIR = os.environ.get("CHAINSAW_RULES_DIR", "/opt/chainsaw/rules")
CHAINSAW_MAPPING = os.environ.get(
    "CHAINSAW_MAPPING", "/opt/chainsaw/mappings/sigma-event-logs-all.yml"
)
HAYABUSA_BIN = os.environ.get("HAYABUSA_BIN", "hayabusa")
HAYABUSA_RULES_DIR = os.environ.get("HAYABUSA_RULES_DIR", "/opt/hayabusa/rules")

# Default subprocess timeout for log-analysis tools (seconds).
_TOOL_TIMEOUT_DEFAULT = 600


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
# EVTX analysis engine (Chainsaw / Hayabusa subprocess helpers)
# ---------------------------------------------------------------------------


def _resolve_evtx_path(rel_path: str) -> str:
    """Resolve a user-supplied path against EVTX_DATA_DIR, blocking traversal.

    Args:
        rel_path: Path to an EVTX file or directory, relative to EVTX_DATA_DIR
            (absolute paths are accepted only if they resolve inside it).

    Returns:
        str: The validated, absolute, real path.

    Raises:
        ValueError: If the resolved path escapes EVTX_DATA_DIR.
        FileNotFoundError: If the resolved path does not exist.
    """
    base = os.path.realpath(EVTX_DATA_DIR)
    target = os.path.realpath(os.path.join(base, rel_path))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError(
            f"Path '{rel_path}' resolves outside the allowed data directory "
            f"('{EVTX_DATA_DIR}'). Only files within it can be analyzed."
        )
    if not os.path.exists(target):
        raise FileNotFoundError(
            f"No such file or directory under the data dir: '{rel_path}'. "
            "Use velociraptor_list_evtx_data to see what is available."
        )
    return target


async def _run_subprocess(
    cmd: List[str], timeout: int
) -> Dict[str, Any]:
    """Run an external command, capturing stdout/stderr with a timeout.

    Args:
        cmd: The argv list (no shell — args are passed directly).
        timeout: Max seconds before the process is killed.

    Returns:
        dict: {"returncode": int, "stdout": str, "stderr": str, "timed_out": bool}.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "timed_out": False,
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True}


def _handle_tool_error(e: Exception, tool: str, bin_name: str) -> str:
    """Format errors for the EVTX analysis subprocess tools."""
    if isinstance(e, FileNotFoundError):
        # Distinguish "binary not on PATH" from "data path missing".
        if bin_name in str(e):
            return (
                f"Error: '{bin_name}' was not found. It is installed in the Docker "
                "image; if running outside the container, install it and set the "
                f"corresponding *_BIN environment variable. ({tool})"
            )
        return f"Error: {e}"
    if isinstance(e, ValueError):
        return f"Error: {e}"
    if isinstance(e, json.JSONDecodeError):
        return (
            f"Error: {tool} produced output that could not be parsed as JSON. The "
            "run may have failed or matched nothing. Check the EVTX path and rules."
        )
    return f"Error: Unexpected {type(e).__name__} in {tool}: {e}"


def _truncate(items: List[Any], limit: int) -> tuple[List[Any], bool]:
    """Cap a result list, returning (items, truncated)."""
    if len(items) > limit:
        return items[:limit], True
    return items, False


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


class DetectionLevel(str, Enum):
    """Severity threshold for Sigma-based detections."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ListEvtxInput(_Base):
    """Input for listing EVTX files available in the data directory."""

    subdir: str = Field(
        default="",
        description="Optional subdirectory under the data dir to list (e.g. a "
        "per-host folder). Empty lists the whole data dir.",
        max_length=512,
    )


class ChainsawHuntInput(_Base):
    """Input for a Chainsaw Sigma hunt over EVTX logs."""

    path: str = Field(
        ...,
        description="EVTX file or directory to hunt through, relative to the data "
        "dir (e.g. 'C.abc123/Security.evtx' or 'C.abc123').",
        min_length=1,
        max_length=1024,
    )
    level: Optional[DetectionLevel] = Field(
        default=None,
        description="Only load rules at or above this severity (omit for all levels).",
    )
    max_results: int = Field(
        default=200, description="Max detections to return.", ge=1, le=2000
    )
    timeout: int = Field(
        default=_TOOL_TIMEOUT_DEFAULT,
        description="Max seconds to let the hunt run.",
        ge=10,
        le=3600,
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class ChainsawSearchInput(_Base):
    """Input for a Chainsaw raw search over EVTX logs."""

    path: str = Field(
        ...,
        description="EVTX file or directory to search, relative to the data dir.",
        min_length=1,
        max_length=1024,
    )
    pattern: str = Field(
        ...,
        description="String or regular expression to search for (e.g. 'mimikatz').",
        min_length=1,
        max_length=1024,
    )
    ignore_case: bool = Field(
        default=True, description="Case-insensitive matching."
    )
    max_results: int = Field(
        default=200, description="Max matching events to return.", ge=1, le=2000
    )
    timeout: int = Field(
        default=_TOOL_TIMEOUT_DEFAULT, description="Max seconds.", ge=10, le=3600
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class HayabusaTimelineInput(_Base):
    """Input for a Hayabusa JSON timeline over EVTX logs."""

    path: str = Field(
        ...,
        description="EVTX file or directory to analyze, relative to the data dir.",
        min_length=1,
        max_length=1024,
    )
    min_level: DetectionLevel = Field(
        default=DetectionLevel.LOW,
        description="Minimum rule severity to load (default: low).",
    )
    max_results: int = Field(
        default=200, description="Max timeline events to return.", ge=1, le=2000
    )
    timeout: int = Field(
        default=_TOOL_TIMEOUT_DEFAULT, description="Max seconds.", ge=10, le=3600
    )
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


@mcp.tool(
    name="velociraptor_list_evtx_data",
    annotations={
        "title": "List Available EVTX Files",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def velociraptor_list_evtx_data(params: ListEvtxInput) -> str:
    """List EVTX (Windows event log) files available for analysis in the data dir.

    These are the files Chainsaw and Hayabusa can analyze. Collect them onto the
    shared data directory (EVTX_DATA_DIR, default /data) using Velociraptor — e.g.
    via the velociraptor_collect_artifact tool with an EVTX-collecting artifact —
    then point the analysis tools at the listed paths.

    Args:
        params (ListEvtxInput):
            - subdir (str, optional): Subdirectory under the data dir to list.

    Returns:
        str: JSON {"data_dir": str, "count": int, "files": [{"path": str,
        "size_bytes": int}]} where paths are relative to the data dir.
        On failure: "Error: <message>".
    """
    try:
        base = _resolve_evtx_path(params.subdir) if params.subdir else os.path.realpath(
            EVTX_DATA_DIR
        )
        if not os.path.isdir(base):
            return f"Error: '{params.subdir or EVTX_DATA_DIR}' is not a directory."
        root = os.path.realpath(EVTX_DATA_DIR)
        files = []
        for dirpath, _dirs, filenames in os.walk(base):
            for fn in filenames:
                if fn.lower().endswith(".evtx"):
                    full = os.path.join(dirpath, fn)
                    files.append(
                        {
                            "path": os.path.relpath(full, root),
                            "size_bytes": os.path.getsize(full),
                        }
                    )
        files.sort(key=lambda f: f["path"])
        return json.dumps(
            {"data_dir": EVTX_DATA_DIR, "count": len(files), "files": files},
            indent=2,
        )
    except Exception as e:  # noqa: BLE001
        return _handle_tool_error(e, "list_evtx_data", "")


@mcp.tool(
    name="chainsaw_hunt",
    annotations={
        "title": "Chainsaw Sigma Hunt",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def chainsaw_hunt(params: ChainsawHuntInput) -> str:
    """Hunt through EVTX logs with Chainsaw using Sigma + Chainsaw detection rules.

    Chainsaw (WithSecure) rapidly applies Sigma rules to Windows event logs and
    surfaces detections grouped by rule. Ideal for fast triage of logs collected
    from an endpoint by Velociraptor.

    Args:
        params (ChainsawHuntInput):
            - path (str): EVTX file/dir relative to the data dir.
            - level (DetectionLevel, optional): Minimum rule severity.
            - max_results (int): Cap on returned detections (default 200).
            - timeout (int): Max run seconds (default 600).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Detections as markdown or JSON. Each detection includes the matched
        rule name(s), timestamp, event ID, and event data. On failure: "Error: <message>".

    Examples:
        - "Triage the Security log from C.abc123 for critical hits" ->
          path="C.abc123/Security.evtx", level="critical"
    """
    try:
        target = _resolve_evtx_path(params.path)
        cmd = [CHAINSAW_BIN, "hunt", target, "--json", "-q"]
        # Chainsaw's own rules are always useful; add Sigma + mapping if present.
        if os.path.isdir(CHAINSAW_RULES_DIR):
            cmd += ["-r", CHAINSAW_RULES_DIR]
        if os.path.isdir(CHAINSAW_SIGMA_DIR) and os.path.isfile(CHAINSAW_MAPPING):
            cmd += ["-s", CHAINSAW_SIGMA_DIR, "--mapping", CHAINSAW_MAPPING]
        if params.level is not None:
            cmd += ["--level", params.level.value]

        result = await _run_subprocess(cmd, params.timeout)
        if result["timed_out"]:
            return (
                f"Error: chainsaw hunt timed out after {params.timeout}s. Narrow the "
                "path to fewer/smaller EVTX files or raise the timeout."
            )
        stdout = result["stdout"].strip()
        if not stdout:
            if result["returncode"] != 0:
                return (
                    "Error: chainsaw hunt failed (exit "
                    f"{result['returncode']}): {result['stderr'].strip()[:800]}"
                )
            return "No detections found."
        detections = json.loads(stdout)
        items, truncated = _truncate(
            detections if isinstance(detections, list) else [detections],
            params.max_results,
        )
        return _format_rows(
            items, [], truncated, params.response_format, "Chainsaw detections"
        )
    except Exception as e:  # noqa: BLE001
        return _handle_tool_error(e, "chainsaw_hunt", CHAINSAW_BIN)


@mcp.tool(
    name="chainsaw_search",
    annotations={
        "title": "Chainsaw Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def chainsaw_search(params: ChainsawSearchInput) -> str:
    """Search raw EVTX records for a string or regex with Chainsaw (no rules).

    Use this to find specific indicators (a filename, IP, account, or tool name)
    across event logs, independent of detection rules.

    Args:
        params (ChainsawSearchInput):
            - path (str): EVTX file/dir relative to the data dir.
            - pattern (str): String or regex to match.
            - ignore_case (bool): Case-insensitive (default True).
            - max_results (int): Cap on returned events (default 200).
            - timeout (int): Max run seconds (default 600).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Matching event records as markdown or JSON. On failure: "Error: <message>".

    Examples:
        - "Find any 'mimikatz' references in C.abc123's logs" ->
          path="C.abc123", pattern="mimikatz"
    """
    try:
        target = _resolve_evtx_path(params.path)
        cmd = [CHAINSAW_BIN, "search", params.pattern, target, "--json", "-q"]
        if params.ignore_case:
            cmd.append("-i")

        result = await _run_subprocess(cmd, params.timeout)
        if result["timed_out"]:
            return f"Error: chainsaw search timed out after {params.timeout}s."
        stdout = result["stdout"].strip()
        if not stdout:
            if result["returncode"] != 0:
                return (
                    "Error: chainsaw search failed (exit "
                    f"{result['returncode']}): {result['stderr'].strip()[:800]}"
                )
            return f"No events matched '{params.pattern}'."
        matches = json.loads(stdout)
        items, truncated = _truncate(
            matches if isinstance(matches, list) else [matches], params.max_results
        )
        return _format_rows(
            items,
            [],
            truncated,
            params.response_format,
            f"Chainsaw search: '{params.pattern}'",
        )
    except Exception as e:  # noqa: BLE001
        return _handle_tool_error(e, "chainsaw_search", CHAINSAW_BIN)


@mcp.tool(
    name="hayabusa_timeline",
    annotations={
        "title": "Hayabusa Forensic Timeline",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def hayabusa_timeline(params: HayabusaTimelineInput) -> str:
    """Generate a Sigma-based forensic timeline from EVTX logs with Hayabusa.

    Hayabusa (Yamato Security) produces a chronological, deduplicated timeline of
    notable events with full Sigma support (including correlation rules). It
    complements Chainsaw: Chainsaw is fast rule-grouped triage, Hayabusa gives a
    time-ordered narrative of an incident.

    Runs non-interactively (no scan wizard); rule severity is controlled by min_level.

    Args:
        params (HayabusaTimelineInput):
            - path (str): EVTX file/dir relative to the data dir.
            - min_level (DetectionLevel): Minimum rule severity (default: low).
            - max_results (int): Cap on returned events (default 200).
            - timeout (int): Max run seconds (default 600).
            - response_format: 'markdown' or 'json'.

    Returns:
        str: Timeline events as markdown or JSON, each with timestamp, rule title,
        level, computer, channel, event ID, and details. On failure: "Error: <message>".

    Examples:
        - "Build an incident timeline from C.abc123's collected logs" ->
          path="C.abc123", min_level="medium"
    """
    out_path = None
    try:
        target = _resolve_evtx_path(params.path)
        input_flag = "-d" if os.path.isdir(target) else "-f"

        fd, out_path = tempfile.mkstemp(suffix=".json", prefix="hayabusa_")
        os.close(fd)

        cmd = [
            HAYABUSA_BIN,
            "json-timeline",
            input_flag,
            target,
            "-o",
            out_path,
            "-w",  # no wizard: run non-interactively
            "-m",
            params.min_level.value,
            "-q",  # no banner
            "-K",  # no color
            "-C",  # clobber/overwrite output file
            "-N",  # skip results summary for speed
        ]
        if os.path.isdir(HAYABUSA_RULES_DIR):
            cmd += ["-r", HAYABUSA_RULES_DIR]

        result = await _run_subprocess(cmd, params.timeout)
        if result["timed_out"]:
            return (
                f"Error: hayabusa timed out after {params.timeout}s. Narrow the path "
                "or raise min_level/timeout."
            )

        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read().strip()
        except OSError:
            content = ""

        if not content:
            if result["returncode"] != 0:
                return (
                    "Error: hayabusa failed (exit "
                    f"{result['returncode']}): {result['stderr'].strip()[:800]}"
                )
            return "No timeline events were generated (no matching detections)."

        events = json.loads(content)
        items, truncated = _truncate(
            events if isinstance(events, list) else [events], params.max_results
        )
        return _format_rows(
            items, [], truncated, params.response_format, "Hayabusa timeline"
        )
    except Exception as e:  # noqa: BLE001
        return _handle_tool_error(e, "hayabusa_timeline", HAYABUSA_BIN)
    finally:
        if out_path and os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass


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
