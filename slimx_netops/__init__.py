"""SlimX-NetOps: the bounded, READ-ONLY network telemetry bridge of the SlimX platform.

One job: expose read-only network/observability reads (SSH show, SNMP GET/WALK, Prometheus,
Alertmanager, logs) as MCP-over-HTTP tools, behind a command/OID allowlist and a device-inventory
egress boundary. It deliberately does NOT own connector registries, approval policy, or UI — those
stay with the host application (SlimX-AI ControlRoom), which reaches this bridge as a remote MCP
connector through its one bounded MCP boundary.

Consumption:
- **Service mode**: run ``slimx_netops.service:app`` (see the Dockerfile) and POST JSON-RPC to
  ``/mcp`` (``tools/list`` / ``tools/call``). Auth via ``SLIMX_NETOPS_INTERNAL_TOKEN``.
- **Package mode**: ``from slimx_netops.mcp import handle_tools_call`` for in-process use/tests.

Modes: ``NETOPS_MODE=fixture`` (default; replays the canonical scenario fixtures) or ``live`` (the
real read-only clients; needs the ``[live]`` extra + an inventory + credentials + a security review).
"""

from __future__ import annotations

__version__ = "0.4.1"

__all__ = ["__version__"]
