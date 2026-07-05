"""Live, READ-ONLY telemetry clients. Constructed only when ``NETOPS_MODE=live``.

Heavy device libraries (netmiko, pysnmp) are imported lazily *inside* the methods that use them,
so importing this module — or running fixture-mode/CI — never requires the ``[live]`` extra.

Read-only guarantees are structural, not just by convention:
- SSH uses netmiko ``send_command`` only (never ``send_config_set``); config mode is never entered,
  and the command has already passed ``allowlist.validate_show_command``.
- SNMP issues GET/WALK PDUs only (never SET); OIDs have passed ``allowlist.validate_oid``.
- Prometheus/Alertmanager/Loki calls are HTTP GETs to read endpoints whose *paths* this module
  constructs — a caller-supplied query string can never change the endpoint path.

This module is on the path to real infrastructure. It must not be enabled without the security
review of ``allowlist.py`` called for in the staged plan.
"""

from __future__ import annotations

from typing import Any

from slimx_netops.config import Settings
from slimx_netops.inventory import Device, Endpoint, resolve_secret
from slimx_netops.results import RawResult, ToolError


class LiveSource:
    def __init__(self, settings: Settings) -> None:
        self._s = settings

    # --- SSH (netmiko) -------------------------------------------------------------------------

    def ssh_show(self, device: Device, command: str) -> RawResult:
        try:
            from netmiko import ConnectHandler  # type: ignore
        except Exception as exc:  # pragma: no cover - live-only dependency
            raise ToolError("live SSH requires the [live] extra (netmiko not installed)") from exc

        params = {
            "device_type": device.platform,
            "host": device.host,
            "port": device.port,
            "username": resolve_secret(device.username),
            "password": resolve_secret(device.password),
            "secret": resolve_secret(device.secret) or "",
            "conn_timeout": self._s.ssh_timeout_seconds,
            "fast_cli": False,
        }
        if not params["username"] or not params["password"]:
            raise ToolError(f"missing SSH credentials for {device.id} (check inventory env vars)")
        try:
            with ConnectHandler(**params) as conn:  # type: ignore[arg-type]
                # send_command runs ONE show command; we never call send_config_set / config_mode.
                output = conn.send_command(command, read_timeout=self._s.ssh_timeout_seconds)
        except Exception as exc:  # pragma: no cover - live-only path
            raise ToolError(f"SSH read failed on {device.id}: {type(exc).__name__}") from exc
        text, truncated = _cap_text(output, self._s.max_output_bytes)
        return RawResult(data=text, format="text", truncated=truncated, command=command)

    # --- SNMP (pysnmp) -------------------------------------------------------------------------

    def snmp_get(self, device: Device, oids: list[str]) -> RawResult:
        rows = {oid: self._snmp_one(device, oid, walk=False) for oid in oids}
        return RawResult(data=rows, format="json", command=f"snmp get {len(oids)} oid(s)")

    def snmp_walk(self, device: Device, oid: str) -> RawResult:
        rows = self._snmp_one(device, oid, walk=True)
        return RawResult(data=rows, format="json", command=f"snmp walk {oid}")

    def _snmp_one(self, device: Device, oid: str, *, walk: bool) -> Any:  # pragma: no cover
        # pysnmp packaging varies across major versions; the sync hlapi is the target. This path is
        # exercised only in live mode against real gear and is validated during live-enablement.
        try:
            from pysnmp.hlapi import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
                nextCmd,
            )
        except Exception as exc:
            raise ToolError(
                "live SNMP requires the [live] extra and a sync-capable pysnmp build"
            ) from exc

        community = resolve_secret(_auth_value(device, "community")) or "public"
        engine = SnmpEngine()
        target = UdpTransportTarget((device.host, 161), timeout=self._s.snmp_timeout_seconds)
        auth = CommunityData(community, mpModel=1)
        cmd = nextCmd if walk else getCmd
        result: dict[str, Any] = {}
        iterator = cmd(engine, auth, target, ContextData(), ObjectType(ObjectIdentity(oid)),
                       lexicographicMode=False)
        for error_indication, error_status, _idx, var_binds in iterator:
            if error_indication or error_status:
                raise ToolError(f"SNMP error on {device.id}: {error_indication or error_status}")
            for name, value in var_binds:
                result[str(name)] = str(value)
            if len(result) >= 4096:
                break
        return result

    # --- HTTP telemetry (httpx) ----------------------------------------------------------------

    def prometheus_query(
        self, endpoint: Endpoint, *, query: str, type_: str, start: str | None,
        end: str | None, step: str | None,
    ) -> RawResult:
        path = "/api/v1/query_range" if type_ == "range" else "/api/v1/query"
        params: dict[str, str] = {"query": query}
        if type_ == "range":
            params.update({k: v for k, v in {"start": start, "end": end, "step": step}.items() if v})
        data = self._http_get_json(endpoint, path, params)
        return RawResult(data=data, format="json", command=f"{type_} {query}")

    def alertmanager_alerts(
        self, endpoint: Endpoint, *, active: bool, silenced: bool, filters: list[str]
    ) -> RawResult:
        params: list[tuple[str, str]] = [
            ("active", str(active).lower()),
            ("silenced", str(silenced).lower()),
        ]
        params.extend(("filter", f) for f in filters)
        data = self._http_get_json(endpoint, "/api/v2/alerts", params)
        return RawResult(data={"alerts": data}, format="json", command="GET /api/v2/alerts")

    def logs_query(
        self, endpoint: Endpoint, *, query: str, start: str | None, end: str | None, limit: int
    ) -> RawResult:
        if endpoint.kind != "loki":
            raise ToolError(f"logs_query live mode supports Loki endpoints only (got {endpoint.kind})")
        params: dict[str, str] = {"query": query, "limit": str(min(limit, self._s.logs_max_lines))}
        params.update({k: v for k, v in {"start": start, "end": end}.items() if v})
        data = self._http_get_json(endpoint, "/loki/api/v1/query_range", params)
        return RawResult(data=data, format="json", command=query)

    def _http_get_json(
        self, endpoint: Endpoint, path: str, params: Any
    ) -> Any:  # pragma: no cover - live-only path
        import httpx

        url = endpoint.base_url.rstrip("/") + path
        headers = _auth_headers(endpoint)
        try:
            resp = httpx.get(
                url, params=params, headers=headers, timeout=self._s.http_timeout_seconds
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise ToolError(f"{endpoint.id} returned HTTP {exc.response.status_code}") from exc
        except Exception as exc:
            raise ToolError(f"{endpoint.id} read failed: {type(exc).__name__}") from exc


def _cap_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = (text or "").encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _auth_value(device: Device, key: str) -> str | None:
    # SNMP community can be carried on the device entry's secret field (env placeholder).
    return device.secret if key == "community" else None


def _auth_headers(endpoint: Endpoint) -> dict[str, str]:
    auth = endpoint.auth or {}
    kind = str(auth.get("type") or "").lower()
    if kind == "bearer":
        token = resolve_secret(auth.get("token"))
        if token:
            return {"Authorization": f"Bearer {token}"}
    if kind == "basic":
        import base64

        user = resolve_secret(auth.get("username")) or ""
        pw = resolve_secret(auth.get("password")) or ""
        raw = base64.b64encode(f"{user}:{pw}".encode()).decode()
        return {"Authorization": f"Basic {raw}"}
    return {}
