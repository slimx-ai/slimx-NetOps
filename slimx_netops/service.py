"""SlimX-NetOps service mode: the read-only telemetry bridge as an MCP-over-HTTP server.

Runs as its own container on the compose-internal network (no host-published port). ControlRoom
adds it as a remote MCP connector and reaches it through the one bounded MCP boundary; the agent's
``mcp_call`` step (grant ``mcp_tools`` + per-connector ``allowedTools``) invokes the tools.

Endpoints:
  POST /mcp    — JSON-RPC 2.0: ``initialize`` (no-op), ``tools/list``, ``tools/call``
  GET  /health — liveness + mode + auth_enabled (for the compose healthcheck / deep health)

Auth: ``SLIMX_NETOPS_INTERNAL_TOKEN`` — when set, ``/mcp`` requires ``Authorization: Bearer <token>``
(constant-time compare). Unset = auth off (local-first). ``/health`` is always open and reports
``auth_enabled`` so a one-sided token is visible.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from slimx_netops import __version__
from slimx_netops.config import get_settings
from slimx_netops.mcp import handle_tools_call, handle_tools_list

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("slimx_netops")

app = FastAPI(title="SlimX-NetOps", version=__version__)


def _token() -> str:
    return os.environ.get("SLIMX_NETOPS_INTERNAL_TOKEN", "").strip()


def _authorized(request: Request) -> bool:
    token = _token()
    if not token:
        return True
    header = request.headers.get("authorization")
    return header is not None and secrets.compare_digest(header, f"Bearer {token}")


@app.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "slimx-netops",
        "version": __version__,
        "mode": settings.mode,
        "auth_enabled": bool(_token()),
    }


def _jsonrpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> JSONResponse:
    if not _authorized(request):
        return JSONResponse(
            status_code=401, content=_jsonrpc_error(None, -32001, "invalid internal service token")
        )
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(status_code=400, content=_jsonrpc_error(None, -32700, "parse error"))
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400, content=_jsonrpc_error(None, -32600, "invalid request")
        )

    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    if method == "initialize":
        return JSONResponse(
            content=_jsonrpc_result(
                request_id,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "slimx-netops", "version": __version__},
                    "capabilities": {"tools": {}},
                },
            )
        )
    if method == "tools/list":
        return JSONResponse(content=_jsonrpc_result(request_id, handle_tools_list()))
    if method == "tools/call":
        result = handle_tools_call(params if isinstance(params, dict) else {})
        return JSONResponse(content=_jsonrpc_result(request_id, result))

    return JSONResponse(
        status_code=404, content=_jsonrpc_error(request_id, -32601, f"method not found: {method}")
    )
