"""Telemetry sources: the read-only backends behind the MCP tools.

- ``FixtureSource`` (default) replays the canonical fixtures — deterministic, no gear, no creds.
  It is what powers demos and CI, and what the ControlRoom integration tests exercise.
- ``LiveSource`` (``slimx_netops.live``, lazy-imported) issues the real read-only calls. It is
  only constructed when ``NETOPS_MODE=live``; its heavy deps live in the ``[live]`` extra.

Both satisfy the ``TelemetrySource`` protocol. The MCP layer resolves the target from the
inventory and enforces the allowlist *before* calling a source, so a source only ever receives a
validated command/OID and an in-inventory target.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Protocol

from slimx_netops.config import Settings, get_settings
from slimx_netops.inventory import Device, Endpoint
from slimx_netops.results import RawResult, ToolError


class TelemetrySource(Protocol):
    def ssh_show(self, device: Device, command: str) -> RawResult: ...
    def snmp_get(self, device: Device, oids: list[str]) -> RawResult: ...
    def snmp_walk(self, device: Device, oid: str) -> RawResult: ...
    def prometheus_query(
        self, endpoint: Endpoint, *, query: str, type_: str, start: str | None,
        end: str | None, step: str | None,
    ) -> RawResult: ...
    def alertmanager_alerts(
        self, endpoint: Endpoint, *, active: bool, silenced: bool, filters: list[str]
    ) -> RawResult: ...
    def logs_query(
        self, endpoint: Endpoint, *, query: str, start: str | None, end: str | None, limit: int
    ) -> RawResult: ...
    def apply_config(self, device: Device, commands: list[str]) -> RawResult: ...


# Process-level simulated write state for FIXTURE mode: device id -> {setting: value}. Lets a
# fixture-mode apply/rollback be reflected in subsequent config reads (so Mode 4/5 demos faithfully
# show before -> after -> rollback), without touching the on-disk fixtures. Never used in live mode.
_FIXTURE_WRITE_STATE: dict[str, dict[str, int]] = {}
_LIFETIME_SET_RE = re.compile(
    r"set\s+security-association\s+lifetime\s+seconds\s+(\d+)", re.IGNORECASE
)
_LIFETIME_CONFIG_RE = re.compile(
    r"(security-association\s+lifetime\s+seconds\s+)(\d+)", re.IGNORECASE
)


# --- Fixture source ----------------------------------------------------------------------------

# ssh_show routing: ordered (substring-in-command, fixture-file, per-device?) rules. First match
# wins; device-specific rules disambiguate the two firewall configs.
_SSH_RULES: tuple[tuple[tuple[str, ...], str, bool], ...] = (
    (("crypto", "ipsec", "sa"), "crypto_ipsec_sa.txt", False),
    (("crypto", "session"), "crypto_ipsec_sa.txt", False),
    (("bgp", "summary"), "bgp_summary.txt", False),
    (("bgp", "neighbor"), "bgp_neighbor_detail.txt", False),
    (("running-config",), "config_{device}_phase2.txt", True),
    (("crypto", "ipsec"), "config_{device}_phase2.txt", True),
    (("logging",), "ike_rekey_logs.txt", False),
    (("ike",), "ike_rekey_logs.txt", False),
    (("ipsec",), "ike_rekey_logs.txt", False),
)

_SIGNALS: dict[str, list[dict[str, Any]]] = {
    "crypto_ipsec_sa.txt": [
        {"key": "phase2_lifetime_seconds", "value": 3600, "unit": "s"},
        {"key": "last_rekey_at", "value": "2026-07-05T09:14:03Z"},
    ],
    "ike_rekey_logs.txt": [
        {"key": "rekey_interval_seconds_est", "value": 3600},
        {"key": "local_lifetime_seconds", "value": 3600},
        {"key": "peer_lifetime_seconds", "value": 28800},
    ],
    "bgp_summary.txt": [
        {"key": "neighbor", "value": "10.20.0.1"},
        {"key": "resets_since_start", "value": 14},
        {"key": "uptime", "value": "00:00:58"},
    ],
    "bgp_neighbor_detail.txt": [
        {"key": "last_reset_reason", "value": "hold time expired"},
        {"key": "resets_since_start", "value": 14},
        {"key": "reset_after_rekey_seconds", "value": 19},
    ],
    "config_edge_fw_a_phase2.txt": [{"key": "phase2_lifetime_seconds", "value": 28800}],
    "config_edge_fw_b_phase2.txt": [{"key": "phase2_lifetime_seconds", "value": 3600}],
    "interface_counters.json": [
        {"key": "ifInErrors.GigabitEthernet0/0", "value": 421},
        {"key": "Tunnel0.resets_last_24h", "value": 24},
    ],
    "prometheus_vpn_tunnel_up.json": [{"key": "tunnel_down_events", "value": 3}],
    "alertmanager_alerts.json": [
        {"key": "active_alertnames", "value": ["BGPNeighborDown", "VPNTunnelFlapping"]}
    ],
    "syslog_timeline.txt": [
        {"key": "tunnel_rekey_at", "value": "2026-07-05T09:14:03Z"},
        {"key": "bgp_reset_at", "value": "2026-07-05T09:14:22Z"},
        {"key": "reset_after_rekey_seconds", "value": 19},
    ],
}


class FixtureSource:
    """Replays the canonical fixtures for the 'BGP resets after VPN flap' scenario."""

    def __init__(self, fixtures_dir: str | Path) -> None:
        self._dir = Path(fixtures_dir)

    def _read_text(self, name: str) -> str:
        path = self._dir / name
        if not path.exists():
            raise ToolError(f"no fixture available for this request (missing {name})")
        return path.read_text(encoding="utf-8")

    def _read_json(self, name: str) -> Any:
        return json.loads(self._read_text(name))

    def ssh_show(self, device: Device, command: str) -> RawResult:
        lowered = command.lower()
        for needles, template, per_device in _SSH_RULES:
            if all(n in lowered for n in needles):
                slug = device.id.replace("-", "_")
                name = template.format(device=slug) if per_device else template
                text = self._read_text(name)
                # Reflect any simulated write for this device (fixture-mode Mode 4/5 demo).
                override = _FIXTURE_WRITE_STATE.get(device.id, {})
                if "phase2_lifetime_seconds" in override:
                    text = _LIFETIME_CONFIG_RE.sub(
                        rf"\g<1>{override['phase2_lifetime_seconds']}", text
                    )
                return RawResult(
                    data=text,
                    format="text",
                    signals=_SIGNALS.get(name, []),
                    command=command,
                )
        raise ToolError(
            f"no fixture matches command {command!r} for {device.id} "
            "(fixture mode ships the VPN/BGP-flap scenario only)"
        )

    def apply_config(self, device: Device, commands: list[str]) -> RawResult:
        """Simulate applying config lines (fixture mode records a write-state override so subsequent
        config reads reflect the change; nothing touches a real device).

        When ``NETOPS_FIXTURE_SIMULATE_WRITES=false`` the override is NOT recorded — the device
        "accepts" the change but does not reflect it, so post-change validation fails and Mode-5
        auto-rollback fires. This is how the rollback path is exercised without real gear."""
        reflect = get_settings().fixture_simulate_writes
        for line in commands:
            match = _LIFETIME_SET_RE.search(line)
            if match and reflect:
                _FIXTURE_WRITE_STATE.setdefault(device.id, {})[
                    "phase2_lifetime_seconds"
                ] = int(match.group(1))
        note = "" if reflect else " (not reflected — simulating a device that did not apply it)"
        return RawResult(
            data=f"(simulated) applied {len(commands)} config line(s) on {device.id}{note}",
            format="text",
            command="configure",
        )

    def snmp_get(self, device: Device, oids: list[str]) -> RawResult:
        return self.snmp_walk(device, oids[0] if oids else "1.3.6.1.2.1.2.2.1")

    def snmp_walk(self, device: Device, oid: str) -> RawResult:
        payload = self._read_json("interface_counters.json")
        payload.pop("_source", None)
        return RawResult(
            data=payload,
            format="json",
            signals=_SIGNALS["interface_counters.json"],
            command=f"snmp {oid}",
        )

    def prometheus_query(
        self, endpoint: Endpoint, *, query: str, type_: str, start: str | None,
        end: str | None, step: str | None,
    ) -> RawResult:
        payload = self._read_json("prometheus_vpn_tunnel_up.json")
        payload.pop("_source", None)
        return RawResult(
            data=payload,
            format="json",
            signals=_SIGNALS["prometheus_vpn_tunnel_up.json"],
            command=f"{type_} {query}",
        )

    def alertmanager_alerts(
        self, endpoint: Endpoint, *, active: bool, silenced: bool, filters: list[str]
    ) -> RawResult:
        payload = self._read_json("alertmanager_alerts.json")
        payload.pop("_source", None)
        return RawResult(
            data=payload,
            format="json",
            signals=_SIGNALS["alertmanager_alerts.json"],
            command="GET /api/v2/alerts",
        )

    def logs_query(
        self, endpoint: Endpoint, *, query: str, start: str | None, end: str | None, limit: int
    ) -> RawResult:
        return RawResult(
            data=self._read_text("syslog_timeline.txt"),
            format="text",
            signals=_SIGNALS["syslog_timeline.txt"],
            command=query,
        )


def get_source(settings: Settings | None = None) -> TelemetrySource:
    settings = settings or get_settings()
    if settings.is_live:
        from slimx_netops.live import LiveSource  # lazy: heavy [live] deps

        return LiveSource(settings)
    return FixtureSource(settings.fixtures_dir)
