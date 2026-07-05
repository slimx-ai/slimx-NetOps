"""Security-critical write allowlist: only allowlisted, parameterized, reversible changes."""

from __future__ import annotations

import pytest

from slimx_netops.writelist import (
    LOW_RISK_CHANGE_TYPES,
    WriteNotAllowed,
    plan_change,
    validate_change_request,
)

_BEFORE = "crypto ipsec profile S2S-PROFILE\n set security-association lifetime seconds 3600\n"


def test_valid_ipsec_lifetime_request_passes():
    ct = validate_change_request("ipsec_phase2_lifetime", {"profile": "S2S-PROFILE", "seconds": 28800})
    assert ct.id == "ipsec_phase2_lifetime"
    assert ct.risk == "low"


@pytest.mark.parametrize(
    "change_type,params",
    [
        ("reboot_device", {}),  # unknown change type
        ("ipsec_phase2_lifetime", {"seconds": 28800}),  # missing profile
        ("ipsec_phase2_lifetime", {"profile": "bad name", "seconds": 28800}),  # unsafe profile
        ("ipsec_phase2_lifetime", {"profile": "S2S", "seconds": 5}),  # out of range
        ("ipsec_phase2_lifetime", {"profile": "S2S", "seconds": "lots"}),  # not an int
        ("ipsec_phase2_lifetime", {"profile": "S2S; reload", "seconds": 28800}),  # injection
    ],
)
def test_invalid_change_requests_refused(change_type, params):
    with pytest.raises(WriteNotAllowed):
        validate_change_request(change_type, params)


def test_plan_builds_apply_and_rollback_from_before_state():
    plan = plan_change("ipsec_phase2_lifetime", {"profile": "S2S-PROFILE", "seconds": 28800}, _BEFORE)
    assert plan.apply_commands == [
        "crypto ipsec profile S2S-PROFILE",
        " set security-association lifetime seconds 28800",
    ]
    # Rollback restores the value read from the before-state (3600), and is marked known.
    assert plan.rollback_commands[-1].endswith("3600")
    assert plan.rollback_known is True
    assert plan.validate and plan.validate[0]["tool"] == "ssh_show"
    # The rollback_request is a ready-to-use apply_change that restores the prior value (3600).
    assert plan.rollback_request == {
        "change_type": "ipsec_phase2_lifetime",
        "params": {"profile": "S2S-PROFILE", "seconds": 3600},
    }


def test_rollback_is_flagged_unknown_when_prior_value_absent():
    plan = plan_change("ipsec_phase2_lifetime", {"profile": "S2S", "seconds": 28800}, "no lifetime here")
    assert plan.rollback_known is False


def test_low_risk_allowlist_exposes_the_reversible_change():
    assert "ipsec_phase2_lifetime" in LOW_RISK_CHANGE_TYPES
