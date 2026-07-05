"""The apply_change WRITE tool: off by default, dry-run plans, apply reflects + rolls back."""

from __future__ import annotations

from slimx_netops.mcp import handle_tools_call, handle_tools_list


def _call(dry_run=True, change_type="ipsec_phase2_lifetime", **params):
    args = {
        "name": "apply_change",
        "arguments": {
            "target": "edge-fw-b",
            "change_type": change_type,
            "params": params or {"profile": "S2S-PROFILE", "seconds": 28800},
            "dry_run": dry_run,
        },
    }
    return handle_tools_call(args)


def _env(result):
    assert not result.get("isError"), result
    return result["content"][0]["json"]


def _enable_writes(monkeypatch):
    monkeypatch.setenv("NETOPS_ENABLE_WRITE", "true")
    from slimx_netops import config

    config.get_settings.cache_clear()


def test_write_tool_absent_and_refused_by_default():
    assert "apply_change" not in {t["name"] for t in handle_tools_list()["tools"]}
    result = _call(dry_run=True)
    assert result["isError"] is True
    assert "disabled" in result["content"][0]["text"]


def test_write_tool_listed_when_enabled(monkeypatch):
    _enable_writes(monkeypatch)
    assert "apply_change" in {t["name"] for t in handle_tools_list()["tools"]}


def test_dry_run_plans_without_applying(monkeypatch):
    _enable_writes(monkeypatch)
    env = _env(_call(dry_run=True))
    assert env["dry_run"] is True
    assert env["after"] is None
    assert "3600" in env["before"]  # unchanged
    assert env["apply_commands"][-1].endswith("28800")
    assert env["rollback_commands"][-1].endswith("3600")
    assert env["risk"] == "low" and env["rollback_known"] is True
    # A dry-run must not mutate the simulated device: a subsequent read still shows 3600.
    from slimx_netops.mcp import handle_tools_call
    after = handle_tools_call({
        "name": "ssh_show",
        "arguments": {"target": "edge-fw-b", "command": "show running-config | section crypto ipsec"},
    })
    assert "3600" in after["content"][0]["json"]["data"]


def test_apply_reflects_change_validates_then_rollback_restores(monkeypatch):
    _enable_writes(monkeypatch)
    env = _env(_call(dry_run=False))
    assert env["dry_run"] is False
    assert "28800" in env["after"]  # the change is now visible in the config read-back
    assert env["validated"] is True  # the SPECIFIC intended value took
    # Roll back using the plan's rollback (restore 3600), then confirm.
    back = _env(_call(dry_run=False, profile="S2S-PROFILE", seconds=3600))
    assert "3600" in back["after"]
    assert back["validated"] is True


def test_apply_not_validated_when_device_does_not_reflect(monkeypatch):
    # Simulate a device that ACCEPTS but does not reflect the change -> validation fails (this is
    # what drives Mode-5 auto-rollback in ControlRoom).
    monkeypatch.setenv("NETOPS_FIXTURE_SIMULATE_WRITES", "false")
    _enable_writes(monkeypatch)
    env = _env(_call(dry_run=False))
    assert env["validated"] is False
    assert "3600" in env["after"]  # unchanged — the intended 28800 did not take


def test_unknown_change_type_is_error(monkeypatch):
    _enable_writes(monkeypatch)
    result = _call(dry_run=True, change_type="reboot")
    assert result["isError"] is True
