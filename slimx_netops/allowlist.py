"""The load-bearing safety layer: what a read-only NetOps command/OID is allowed to be.

SECURITY-CRITICAL. This module is the reason a model-driven agent can be pointed at production
network gear without being able to change it. It is deliberately allowlist-first (only explicitly
permitted things pass) with a deny-list as defense-in-depth, kept in code (not env) so it is
reviewable and cannot be silently widened at runtime.

Policy for ``ssh_show``:
1. No shell/CLI metacharacters that could smuggle a second command or a shell escape.
2. The command (and each pipe-filter segment) must *start* with an allowlisted read verb / filter.
   Only ``show`` / ``display`` (+ a couple of read aliases) run; everything else is refused.
3. A deny substring guard catches known shell-escape and file-write tokens even as arguments.

Policy for SNMP OIDs: an OID must be numeric-dotted and sit under an allowlisted read-only root.
The bridge only ever issues GET/WALK PDUs (never SET) — the allowlist additionally bounds *which*
subtree may be read.
"""

from __future__ import annotations

import re

# --- SSH show-command policy -------------------------------------------------------------------

# Leading verbs that are read-only on the major network CLIs (Cisco IOS/NX/XR, Arista, Juniper,
# Huawei). `show`/`display` cover ~all diagnostics. Kept intentionally tiny.
READ_VERBS: frozenset[str] = frozenset({"show", "display"})

# Keywords a `... | <filter>` segment may start with. All are read-only output filters. Notably
# ABSENT (so refused): redirect, tee, append, save, file — anything that writes output somewhere.
FILTER_KEYWORDS: frozenset[str] = frozenset(
    {
        "include", "i", "inc",
        "exclude", "e", "ex",
        "begin", "b", "beg",
        "section", "sec",
        "count",
        "match", "except",
        "grep",
        "no-more", "last", "trim", "find",
    }
)

# Characters that must never appear: command separators, redirection, subshells, expansion.
# (The pipe `|` is handled separately — it is legitimate IOS output filtering.)
_SHELL_METACHARS = re.compile(r"[;&`$><\n\r\t\\]")

# Tokens that must never appear ANYWHERE in the command (shell escapes, config negation that
# some platforms accept mid-line, file writes). Defense in depth on top of the verb allowlist.
DENY_SUBSTRINGS: tuple[str, ...] = (
    "tclsh", "guestshell", "bash", "start shell", "run shell", "python",
    "redirect", "| tee", "|tee", " append", " save ",
    "configure", "config t", "conf t",
    "reload", "reboot", "restart", "erase", "delete", "format",
    "copy ", "write ", " wr ", "commit", "rollback", "request system",
)

MAX_COMMAND_LEN = 512


class AllowlistError(ValueError):
    """A command/OID was rejected by the safety layer. ``reason`` is a short, non-leaking string."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _normalize(command: str) -> str:
    return re.sub(r"\s+", " ", (command or "").strip())


def validate_show_command(command: str) -> str:
    """Return the normalized command if it is a permitted read-only show/display, else raise.

    Never mutates a device: the returned string is only ever handed to a client that runs it as a
    single show command with no config-mode entry.
    """
    normalized = _normalize(command)
    if not normalized:
        raise AllowlistError("empty command")
    if len(normalized) > MAX_COMMAND_LEN:
        raise AllowlistError("command too long")
    if _SHELL_METACHARS.search(normalized):
        raise AllowlistError("command contains a forbidden shell/CLI metacharacter")

    lowered = normalized.lower()
    for bad in DENY_SUBSTRINGS:
        if bad in lowered:
            raise AllowlistError(
                f"command rejected: {bad.strip()!r} is on the deny-list; ssh_show permits "
                "read-only show/display commands only"
            )

    # Split on pipe: the head must be a read verb; each filter segment a read-only filter.
    segments = [seg.strip() for seg in normalized.split("|")]
    head_tokens = segments[0].split(" ", 1)
    verb = head_tokens[0].lower()
    if verb not in READ_VERBS:
        raise AllowlistError(
            f"command must start with one of {sorted(READ_VERBS)}; got {verb!r}. "
            "ssh_show runs read-only show/display commands only"
        )
    if len(head_tokens) < 2 or not head_tokens[1].strip():
        raise AllowlistError("a bare 'show'/'display' with no subject is not allowed")

    for seg in segments[1:]:
        if not seg:
            raise AllowlistError("empty pipe filter segment")
        keyword = seg.split(" ", 1)[0].lower()
        if keyword not in FILTER_KEYWORDS:
            raise AllowlistError(
                f"pipe filter {keyword!r} is not permitted (allowed: {sorted(FILTER_KEYWORDS)}); "
                "output redirection/tee/save is never allowed"
            )
    return normalized


# --- SNMP OID policy ---------------------------------------------------------------------------

# Read-only roots. mib-2 (1.3.6.1.2.1) covers system/interfaces/ip/tcp/udp/snmp — the standard
# read diagnostics. Extend per-deployment via a PR (auditable), never via env.
ALLOWED_OID_ROOTS: tuple[str, ...] = (
    "1.3.6.1.2.1",  # mib-2
)

_OID_RE = re.compile(r"^\.?(\d+)(\.\d+)*$")
MAX_OIDS_PER_CALL = 64


def validate_oid(oid: str) -> str:
    """Return the canonical (leading-dot-stripped) OID if under an allowlisted read root, else raise."""
    candidate = (oid or "").strip()
    if not candidate or not _OID_RE.match(candidate):
        raise AllowlistError(f"invalid OID: {oid!r}")
    canonical = candidate.lstrip(".")
    for root in ALLOWED_OID_ROOTS:
        if canonical == root or canonical.startswith(root + "."):
            return canonical
    raise AllowlistError(
        f"OID {canonical} is not under an allowlisted read-only root {list(ALLOWED_OID_ROOTS)}"
    )


def validate_oids(oids: list[str]) -> list[str]:
    if not oids:
        raise AllowlistError("no OIDs given")
    if len(oids) > MAX_OIDS_PER_CALL:
        raise AllowlistError(f"too many OIDs ({len(oids)} > {MAX_OIDS_PER_CALL})")
    return [validate_oid(o) for o in oids]
