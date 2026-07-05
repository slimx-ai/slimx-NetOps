"""The write-side safety layer: which device changes are allowed, and how each rolls back.

SECURITY-CRITICAL, and the whole write path is OFF by default (``NETOPS_ENABLE_WRITE=false``).
Unlike a generic "run this config line", a change here is a **parameterized, reversible change type**
from a fixed allowlist. Each change type knows:

- the read command to capture BEFORE state,
- how to build the exact apply commands from validated params,
- how to build the ROLLBACK commands (to restore the prior state), and
- what to collect afterwards to VALIDATE the change.

The bridge never executes an arbitrary command on the write path — only an allowlisted change type
with validated params. This bounds the blast radius the way ``allowlist.py`` bounds reads.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# Risk tiers a change type carries; ControlRoom's Mode-5 auto-remediate allowlist keys on "low".
RISK_LOW = "low"
RISK_NORMAL = "normal"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


class WriteNotAllowed(ValueError):
    """A change request was rejected by the write safety layer (unknown type or bad params)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ChangePlan:
    change_type: str
    apply_commands: list[str]
    rollback_commands: list[str]
    validate: list[dict]  # collect specs run after apply, e.g. [{"tool":"ssh_show","command":...}]
    risk: str
    rollback_known: bool  # False when the prior value could not be read (rollback is best-effort)
    # A ready-to-use apply_change call that restores the prior state — for the host's Mode-5
    # auto-rollback. None when the prior value could not be read. For parameterized changes the
    # rollback IS the same change type with the restored param value.
    rollback_request: dict | None


@dataclass(frozen=True)
class ChangeType:
    id: str
    description: str
    risk: str
    read_command: str  # show command to capture before-state
    _validate_params: Callable[[dict], None]
    _build_apply: Callable[[dict], list[str]]
    _build_rollback: Callable[[dict, str], tuple[list[str], bool]]
    _build_rollback_request: Callable[[dict, str], dict | None]
    _validate_specs: Callable[[dict], list[dict]]
    # Given the params and the concatenated text of the validate read-backs, is the SPECIFIC
    # intended change reflected? (Richer than "state changed" — confirms the exact value took.)
    _check_reflected: Callable[[dict, str], bool]


# --- change type: IPsec Phase-2 (IPsec SA) lifetime -------------------------------------------
# The exact, reversible fix for the demo scenario (rekey-lifetime mismatch): set the Phase-2
# lifetime seconds on a device's crypto profile. Rollback restores the value read beforehand.

_LIFETIME_RE = re.compile(r"security-association\s+lifetime\s+seconds\s+(\d+)", re.IGNORECASE)


def _validate_ipsec_lifetime_params(params: dict) -> None:
    profile = str(params.get("profile") or "").strip()
    if not _SAFE_NAME.match(profile):
        raise WriteNotAllowed("ipsec_phase2_lifetime requires a safe 'profile' name")
    try:
        seconds = int(params.get("seconds"))
    except (TypeError, ValueError) as exc:
        raise WriteNotAllowed("ipsec_phase2_lifetime requires integer 'seconds'") from exc
    if not (120 <= seconds <= 86400):
        raise WriteNotAllowed("ipsec_phase2_lifetime 'seconds' must be 120..86400")


def _apply_ipsec_lifetime(params: dict) -> list[str]:
    return [
        f"crypto ipsec profile {params['profile']}",
        f" set security-association lifetime seconds {int(params['seconds'])}",
    ]


def _rollback_ipsec_lifetime(params: dict, before: str) -> tuple[list[str], bool]:
    match = _LIFETIME_RE.search(before or "")
    if not match:
        # Could not read the prior value — rollback would restore the vendor default; flag it.
        return (
            [
                f"crypto ipsec profile {params['profile']}",
                " no set security-association lifetime seconds",
            ],
            False,
        )
    old = int(match.group(1))
    return (
        [
            f"crypto ipsec profile {params['profile']}",
            f" set security-association lifetime seconds {old}",
        ],
        True,
    )


def _rollback_request_ipsec_lifetime(params: dict, before: str) -> dict | None:
    match = _LIFETIME_RE.search(before or "")
    if not match:
        return None
    return {
        "change_type": "ipsec_phase2_lifetime",
        "params": {"profile": params["profile"], "seconds": int(match.group(1))},
    }


CHANGE_TYPES: dict[str, ChangeType] = {
    "ipsec_phase2_lifetime": ChangeType(
        id="ipsec_phase2_lifetime",
        description="Set the IPsec (Phase-2) SA lifetime seconds on a device's crypto profile.",
        risk=RISK_LOW,
        read_command="show running-config | section crypto ipsec",
        _validate_params=_validate_ipsec_lifetime_params,
        _build_apply=_apply_ipsec_lifetime,
        _build_rollback=_rollback_ipsec_lifetime,
        _build_rollback_request=_rollback_request_ipsec_lifetime,
        _validate_specs=lambda params: [
            # Read the config back — that is where the lifetime setting authoritatively lives (the SA
            # only rebuilds with it at the next rekey). Validation confirms the new value is present.
            {"tool": "ssh_show", "command": "show running-config | section crypto ipsec"}
        ],
        # Reflected iff the exact intended lifetime value is present in the read-back config.
        _check_reflected=lambda params, reads: bool(
            re.search(
                rf"security-association\s+lifetime\s+seconds\s+{int(params['seconds'])}\b", reads
            )
        ),
    ),
}

# Change types safe enough to consider for bounded auto-remediation (Mode 5). ControlRoom keys its
# own NETOPS_AUTO_REMEDIATE allowlist on this — the bridge just advertises which changes are low-risk.
LOW_RISK_CHANGE_TYPES: frozenset[str] = frozenset(
    ct_id for ct_id, ct in CHANGE_TYPES.items() if ct.risk == RISK_LOW
)


def validate_change_request(change_type: str, params: dict) -> ChangeType:
    ct = CHANGE_TYPES.get(change_type)
    if ct is None:
        raise WriteNotAllowed(
            f"unknown change_type {change_type!r}; allowed: {sorted(CHANGE_TYPES)}"
        )
    ct._validate_params(params or {})
    return ct


def check_reflected(change_type: str, params: dict, reads: str) -> bool:
    """Is the specific intended change reflected in the validate read-backs? Confirms the exact
    value took, not merely that some state changed."""
    ct = validate_change_request(change_type, params)
    return ct._check_reflected(params, reads or "")


def plan_change(change_type: str, params: dict, before: str) -> ChangePlan:
    """Build the apply/rollback/validate plan for a validated change against the before-state."""
    ct = validate_change_request(change_type, params)
    rollback, rollback_known = ct._build_rollback(params, before)
    return ChangePlan(
        change_type=ct.id,
        apply_commands=ct._build_apply(params),
        rollback_commands=rollback,
        validate=ct._validate_specs(params),
        risk=ct.risk,
        rollback_known=rollback_known,
        rollback_request=ct._build_rollback_request(params, before),
    )
