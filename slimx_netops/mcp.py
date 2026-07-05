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

from slimx_netops import allowlist, inventory, tools, writelist
from slimx_netops.clients import TelemetrySource, get_source
from slimx_netops.config import get_settings
from slimx_netops.results import RawResult, ToolError

logger = logging.getLogger("slimx_netops.mcp")


def handle_tools_list() -> dict[str, Any]:
    return {"tools": tools.tools_list(get_settings().enable_write)}


def handle_tools_call(params: dict[str, Any], source: TelemetrySource | None = None) -> dict[str, Any]:
    source = source or get_source()
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return tools.error_result(str(name), None, "arguments must be an object")
    if name in tools.WRITE_TOOL_NAMES:
        return _handle_apply_change(arguments, source)
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


def _handle_apply_change(arguments: dict[str, Any], source: TelemetrySource) -> dict[str, Any]:
    """The WRITE path: plan (dry-run) or apply ONE allowlisted, reversible change with rollback.

    Gated four ways: NETOPS_ENABLE_WRITE on the bridge, the change_type on the writelist, param
    validation, and (upstream in ControlRoom) the netops_write grant + hard-gate approval. Captures
    before-state, builds apply + rollback commands, and — on a real apply — reads after-state.
    """
    settings = get_settings()
    target = arguments.get("target") if isinstance(arguments.get("target"), str) else None
    if not settings.enable_write:
        return tools.error_result(
            "apply_change", target,
            "writes are disabled on this bridge (set NETOPS_ENABLE_WRITE=true to allow device changes)",
        )
    try:
        args = tools.ApplyChangeInput(**arguments)
        device = inventory.get_device(args.target)
        change_type = writelist.validate_change_request(args.change_type, args.params)
        before = source.ssh_show(device, change_type.read_command).data
        before_text = before if isinstance(before, str) else str(before)
        plan = writelist.plan_change(args.change_type, args.params, before_text)
    except ValidationError as exc:
        return tools.error_result("apply_change", target, _first_validation_message(exc))
    except writelist.WriteNotAllowed as exc:
        return tools.error_result("apply_change", target, exc.reason)
    except inventory.UnknownTargetError:
        return tools.error_result("apply_change", target, f"unknown target {args.target!r}")
    except (inventory.InventoryError, ToolError) as exc:
        return tools.error_result("apply_change", target, str(exc))

    envelope: dict[str, Any] = {
        "tool": "apply_change",
        "target": device.id,
        "change_type": plan.change_type,
        "collected_at": tools._now_iso(),
        "ok": True,
        "dry_run": args.dry_run,
        "risk": plan.risk,
        "rollback_known": plan.rollback_known,
        "apply_commands": plan.apply_commands,
        "rollback_commands": plan.rollback_commands,
        "rollback_request": plan.rollback_request,
        "validate": plan.validate,
        "before": before_text,
        "after": None,
    }
    if args.dry_run:
        return tools.ok_result(envelope)

    try:
        applied = source.apply_config(device, plan.apply_commands)
        after = source.ssh_show(device, change_type.read_command).data
        # Post-change validation: run the change's validate read-backs and confirm the SPECIFIC
        # intended value took (richer than "state changed"). This drives Mode-5 auto-rollback.
        reads: list[str] = []
        for spec in plan.validate:
            cmd = str(spec.get("command") or "")
            if spec.get("tool") == "ssh_show" and cmd:
                data = source.ssh_show(device, cmd).data
                reads.append(data if isinstance(data, str) else str(data))
        reads_text = "\n".join(reads) or (after if isinstance(after, str) else str(after))
    except ToolError as exc:
        return tools.error_result("apply_change", device.id, f"apply failed: {exc}")
    envelope["applied_output"] = applied.data if isinstance(applied.data, str) else str(applied.data)
    envelope["after"] = after if isinstance(after, str) else str(after)
    envelope["validated"] = writelist.check_reflected(args.change_type, args.params, reads_text)
    return tools.ok_result(envelope)


def _first_validation_message(exc: ValidationError) -> str:
    errors = exc.errors()
    if errors:
        loc = ".".join(str(p) for p in errors[0].get("loc", ()))
        return f"{loc}: {errors[0].get('msg', 'invalid')}".strip(": ")
    return "invalid input"
