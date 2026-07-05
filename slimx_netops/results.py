"""Shared result + error types for the telemetry sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RawResult:
    """One read-only collection result, before it is wrapped in the MCP tool envelope.

    ``data`` is the raw output (str for CLI/log text, dict/list for JSON APIs). ``signals`` are
    optional bridge-extracted typed hints; they never replace ``data``.
    """

    data: Any
    format: str = "text"  # "text" | "json" | "table"
    truncated: bool = False
    signals: list[dict[str, Any]] = field(default_factory=list)
    command: str | None = None


class ToolError(RuntimeError):
    """A read failed (unreachable target, timeout, no data). Becomes an ``isError`` tool result.

    Distinct from ``allowlist.AllowlistError`` (a policy refusal) so the two can be logged/tested
    apart, though both surface to the caller as ``isError: true``.
    """
