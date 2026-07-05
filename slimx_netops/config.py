"""Runtime settings for the SlimX-NetOps bridge, all from the environment.

Two modes:
- ``fixture`` (default) — the telemetry source replays the canonical fixtures shipped with the
  package. No device libraries, no credentials, no network to infra. Demos + CI use this.
- ``live`` — the real read-only device/telemetry clients (netmiko/pysnmp/httpx). Requires the
  ``[live]`` extra, a real inventory, and credentials. Turn this on only on the box that reaches
  the devices, and only after the allowlist has had a security review.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_FIXTURES_DIR = _PACKAGE_DIR / "fixtures"


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw.strip() if raw and raw.strip() else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw and raw.strip() else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    mode: str
    inventory_path: str
    fixtures_dir: str
    internal_token: str
    max_output_bytes: int
    ssh_timeout_seconds: int
    snmp_timeout_seconds: int
    http_timeout_seconds: int
    logs_max_lines: int

    @property
    def is_live(self) -> bool:
        return self.mode == "live"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    mode = _env_str("NETOPS_MODE", "fixture").lower()
    if mode not in {"fixture", "live"}:
        mode = "fixture"
    fixtures_dir = _env_str("NETOPS_FIXTURES_DIR", str(_DEFAULT_FIXTURES_DIR))
    inventory_path = _env_str(
        "NETOPS_INVENTORY", str(Path(fixtures_dir) / "inventory.json")
    )
    return Settings(
        mode=mode,
        inventory_path=inventory_path,
        fixtures_dir=fixtures_dir,
        internal_token=_env_str("SLIMX_NETOPS_INTERNAL_TOKEN", ""),
        max_output_bytes=_env_int("NETOPS_MAX_OUTPUT_BYTES", 256_000),
        ssh_timeout_seconds=_env_int("NETOPS_SSH_TIMEOUT_SECONDS", 20),
        snmp_timeout_seconds=_env_int("NETOPS_SNMP_TIMEOUT_SECONDS", 10),
        http_timeout_seconds=_env_int("NETOPS_HTTP_TIMEOUT_SECONDS", 15),
        logs_max_lines=_env_int("NETOPS_LOGS_MAX_LINES", 5000),
    )
