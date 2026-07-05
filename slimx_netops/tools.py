"""Tool schemas (for ``tools/list``) and the frozen MCP tool-result envelope.

The response envelope matches what ControlRoom's ``mcp_runtime._extract_payload`` reads: a single
``content[0]`` block of ``{"type": "json", "json": <envelope>}`` (it returns ``content[0]["json"]``
directly), mirrored in ``structuredContent``. Failures set ``isError: true`` with a human message in
a ``text`` block, which ControlRoom surfaces as a real tool error.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from slimx_netops.results import RawResult


# --- Tool input models -------------------------------------------------------------------------

class SshShowInput(BaseModel):
    target: str
    command: str


class SnmpGetInput(BaseModel):
    target: str
    oids: list[str] = Field(min_length=1)


class SnmpWalkInput(BaseModel):
    target: str
    oid: str


class PrometheusQueryInput(BaseModel):
    target: str
    query: str
    type: str = "instant"  # "instant" | "range"
    start: str | None = None
    end: str | None = None
    step: str | None = None


class AlertmanagerAlertsInput(BaseModel):
    target: str
    active: bool = True
    silenced: bool = False
    filter: list[str] = Field(default_factory=list)


class LogsQueryInput(BaseModel):
    target: str
    query: str
    start: str | None = None
    end: str | None = None
    limit: int = 1000


class ApplyChangeInput(BaseModel):
    """A WRITE request (Stage 4/5). Runs only when NETOPS_ENABLE_WRITE=true and change_type is on the
    writelist. ``dry_run`` (default True) plans without applying."""

    target: str
    change_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True


# --- tools/list --------------------------------------------------------------------------------

_TARGET = {"type": "string", "description": "An inventory target id (device or endpoint)."}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "ssh_show",
        "description": (
            "Run ONE read-only show/display command on a network device over SSH and return its "
            "output. Read-only: only allowlisted show/display commands run; config/exec/write verbs "
            "are refused."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"target": _TARGET, "command": {"type": "string"}},
            "required": ["target", "command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "snmp_get",
        "description": "SNMP GET one or more read-only OIDs (under allowlisted MIB roots).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _TARGET,
                "oids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            },
            "required": ["target", "oids"],
            "additionalProperties": False,
        },
    },
    {
        "name": "snmp_walk",
        "description": "SNMP WALK a read-only OID subtree (under an allowlisted MIB root).",
        "inputSchema": {
            "type": "object",
            "properties": {"target": _TARGET, "oid": {"type": "string"}},
            "required": ["target", "oid"],
            "additionalProperties": False,
        },
    },
    {
        "name": "prometheus_query",
        "description": "Run an instant or range PromQL query (read-only /api/v1/query[_range]).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _TARGET,
                "query": {"type": "string"},
                "type": {"type": "string", "enum": ["instant", "range"]},
                "start": {"type": "string"},
                "end": {"type": "string"},
                "step": {"type": "string"},
            },
            "required": ["target", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "alertmanager_alerts",
        "description": "List Alertmanager alerts (read-only GET /api/v2/alerts). Never posts silences.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _TARGET,
                "active": {"type": "boolean"},
                "silenced": {"type": "boolean"},
                "filter": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "logs_query",
        "description": "Read a bounded slice of a log source (query + time-range + line cap).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _TARGET,
                "query": {"type": "string"},
                "start": {"type": "string"},
                "end": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            "required": ["target", "query"],
            "additionalProperties": False,
        },
    },
]

TOOL_NAMES: frozenset[str] = frozenset(t["name"] for t in TOOLS)

# Write tools (Stage 4/5) — advertised and callable ONLY when NETOPS_ENABLE_WRITE=true.
WRITE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "apply_change",
        "description": (
            "Apply ONE allowlisted, reversible device change (or dry-run it). Read-only unless the "
            "bridge has NETOPS_ENABLE_WRITE=true. Always plan a rollback; prefer dry_run first."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": _TARGET,
                "change_type": {"type": "string", "description": "An allowlisted change type id."},
                "params": {"type": "object"},
                "dry_run": {"type": "boolean", "default": True},
            },
            "required": ["target", "change_type"],
            "additionalProperties": False,
        },
    },
]

WRITE_TOOL_NAMES: frozenset[str] = frozenset(t["name"] for t in WRITE_TOOLS)


def tools_list(enable_write: bool) -> list[dict[str, Any]]:
    """Advertised tools: reads always; the write tool only when the bridge enables writes."""
    return TOOLS + (WRITE_TOOLS if enable_write else [])


# --- Result envelope ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_envelope(tool: str, target: str, raw: RawResult) -> dict[str, Any]:
    return {
        "tool": tool,
        "target": target,
        "command": raw.command,
        "collected_at": _now_iso(),
        "ok": True,
        "truncated": raw.truncated,
        "format": raw.format,
        "data": raw.data,
        "signals": raw.signals,
    }


def ok_result(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "json", "json": envelope}],
        "structuredContent": envelope,
    }


def error_result(tool: str, target: str | None, message: str) -> dict[str, Any]:
    body = {"tool": tool, "target": target, "ok": False, "error": message}
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"{tool}: {message}"}],
        "structuredContent": body,
    }
