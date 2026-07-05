"""Device / telemetry-endpoint inventory — and the target-egress boundary.

The bridge can only reach targets that appear in this inventory. A ``target`` argument that is not
an inventory id is refused (``UnknownTargetError``). This is the authoritative NetOps egress
allowlist described in docs/netops/contract.md: because the bridge holds the credentials, the real
boundary lives here, not in the generic SSRF guard.

Credentials are ``${ENV_VAR}`` placeholders resolved from the process environment at call time
(never stored in the inventory file, never returned to callers). In fixture mode credentials are
unused, so placeholders can stay unset.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from slimx_netops.config import get_settings

_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class UnknownTargetError(KeyError):
    """The requested target id is not in the inventory (so the bridge will not reach it)."""


class InventoryError(RuntimeError):
    """The inventory file is missing or malformed."""


@dataclass(frozen=True)
class Device:
    id: str
    host: str
    platform: str = "cisco_ios"  # netmiko device_type
    port: int = 22
    username: str | None = None
    password: str | None = None
    secret: str | None = None  # enable secret


@dataclass(frozen=True)
class Endpoint:
    id: str
    kind: str  # "prometheus" | "alertmanager" | "loki" | ...
    base_url: str
    auth: dict[str, Any] = field(default_factory=dict)


def resolve_secret(value: str | None) -> str | None:
    """Resolve a ``${VAR}`` placeholder from the environment; pass literals through unchanged."""
    if value is None:
        return None
    match = _PLACEHOLDER.match(value.strip())
    if match:
        return os.environ.get(match.group(1))
    return value


@lru_cache(maxsize=1)
def _raw_inventory() -> dict[str, Any]:
    path = get_settings().inventory_path
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise InventoryError(f"inventory file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InventoryError(f"inventory file is not valid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InventoryError("inventory must be a JSON object")
    return data


def get_device(target: str) -> Device:
    devices = _raw_inventory().get("devices") or {}
    entry = devices.get(target)
    if not isinstance(entry, dict):
        raise UnknownTargetError(target)
    return Device(
        id=target,
        host=str(entry.get("host") or target),
        platform=str(entry.get("platform") or "cisco_ios"),
        port=int(entry.get("port") or 22),
        username=entry.get("username"),
        password=entry.get("password"),
        secret=entry.get("secret"),
    )


def get_endpoint(target: str, *, expected_kind: str | None = None) -> Endpoint:
    endpoints = _raw_inventory().get("endpoints") or {}
    entry = endpoints.get(target)
    if not isinstance(entry, dict):
        raise UnknownTargetError(target)
    endpoint = Endpoint(
        id=target,
        kind=str(entry.get("kind") or ""),
        base_url=str(entry.get("base_url") or ""),
        auth=entry.get("auth") or {},
    )
    if expected_kind is not None and endpoint.kind != expected_kind:
        raise UnknownTargetError(
            f"{target} is a {endpoint.kind or 'unknown'} endpoint, not {expected_kind}"
        )
    return endpoint


def known_targets() -> dict[str, list[str]]:
    inv = _raw_inventory()
    return {
        "devices": sorted((inv.get("devices") or {}).keys()),
        "endpoints": sorted((inv.get("endpoints") or {}).keys()),
    }
