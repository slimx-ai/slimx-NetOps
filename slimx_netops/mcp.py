"""MCP tool dispatch: ``tools/list`` + ``tools/call``.

Order for every call: parse arguments → resolve target from the inventory (target-egress boundary)
→ enforce the allowlist (for ssh/snmp) → call the telemetry source → wrap in the frozen envelope.
Every failure (bad args, unknown target, allowlist refusal, read error, or an unexpected error)
becomes an ``isError`` result — never a fake success, never a leaked stack trace.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError

from slimx_netops import allowlist, inventory, tools
from slimx_netops.clients import TelemetrySource, get_source
from slimx_netops.results import RawResult, ToolError

logger = logging.getLogger("slimx_netops.mcp")


def handle_tools_list() -> dict[str, Any]:
    return {"tools": tools.TOOLS}


def handle_tools_call(params: dict[str, Any], source: TelemetrySource | None = None) -> dict[str, Any]:
    source = source or get_source()
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return tools.error_result(str(name), None, "arguments must be an object")
    if name not in tools.TOOL_NAMES:
        return tools.error_result(str(name), None, f"unknown tool: {name!r}")

    target = arguments.get("target") if isinstance(arguments.get("target"), str) else None
    try:
        raw, resolved_target = _dispatch(name, arguments, source)
    except ValidationError as exc:
        return tools.error_result(name, target, _first_validation_message(exc))
    except allowlist.AllowlistError as exc:
        return tools.error_result(name, target, exc.reason)
    except inventory.UnknownTargetError as exc:
        known = inventory.known_targets()
        return tools.error_result(
            name, target,
            f"unknown target {str(exc).strip(chr(39))!r}; not in inventory. "
            f"Known devices: {known['devices']}; endpoints: {known['endpoints']}",
        )
    except (inventory.InventoryError, ToolError) as exc:
        return tools.error_result(name, target, str(exc))
    except Exception:  # never leak a stack; classify as unknown
        logger.exception("unexpected error in tools/call name=%s", name)
        return tools.error_result(name, target, "unexpected error")

    return tools.ok_result(tools.build_envelope(name, resolved_target, raw))


def _dispatch(
    name: str, arguments: dict[str, Any], source: TelemetrySource
) -> tuple[RawResult, str]:
    if name == "ssh_show":
        args = tools.SshShowInput(**arguments)
        device = inventory.get_device(args.target)
        command = allowlist.validate_show_command(args.command)
        return source.ssh_show(device, command), device.id

    if name == "snmp_get":
        args = tools.SnmpGetInput(**arguments)
        device = inventory.get_device(args.target)
        oids = allowlist.validate_oids(args.oids)
        return source.snmp_get(device, oids), device.id

    if name == "snmp_walk":
        args = tools.SnmpWalkInput(**arguments)
        device = inventory.get_device(args.target)
        oid = allowlist.validate_oid(args.oid)
        return source.snmp_walk(device, oid), device.id

    if name == "prometheus_query":
        args = tools.PrometheusQueryInput(**arguments)
        endpoint = inventory.get_endpoint(args.target, expected_kind="prometheus")
        raw = source.prometheus_query(
            endpoint, query=args.query, type_=args.type, start=args.start,
            end=args.end, step=args.step,
        )
        return raw, endpoint.id

    if name == "alertmanager_alerts":
        args = tools.AlertmanagerAlertsInput(**arguments)
        endpoint = inventory.get_endpoint(args.target, expected_kind="alertmanager")
        raw = source.alertmanager_alerts(
            endpoint, active=args.active, silenced=args.silenced, filters=args.filter
        )
        return raw, endpoint.id

    if name == "logs_query":
        args = tools.LogsQueryInput(**arguments)
        endpoint = inventory.get_endpoint(args.target)
        raw = source.logs_query(
            endpoint, query=args.query, start=args.start, end=args.end, limit=args.limit
        )
        return raw, endpoint.id

    raise ToolError(f"no dispatch for tool {name!r}")  # unreachable (guarded by TOOL_NAMES)


def _first_validation_message(exc: ValidationError) -> str:
    errors = exc.errors()
    if errors:
        loc = ".".join(str(p) for p in errors[0].get("loc", ()))
        return f"{loc}: {errors[0].get('msg', 'invalid')}".strip(": ")
    return "invalid input"
