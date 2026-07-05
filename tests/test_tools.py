"""tools/list + tools/call over the fixture source: the frozen envelope + honest errors."""

from __future__ import annotations

from slimx_netops.mcp import handle_tools_call, handle_tools_list


def _envelope(result: dict) -> dict:
    assert not result.get("isError"), result
    block = result["content"][0]
    assert block["type"] == "json"
    return block["json"]


def test_tools_list_advertises_all_six():
    names = {t["name"] for t in handle_tools_list()["tools"]}
    assert names == {
        "ssh_show", "snmp_get", "snmp_walk",
        "prometheus_query", "alertmanager_alerts", "logs_query",
    }


def test_ssh_show_crypto_returns_lifetime_signal():
    result = handle_tools_call(
        {"name": "ssh_show", "arguments": {"target": "edge-fw-b", "command": "show crypto ipsec sa"}}
    )
    env = _envelope(result)
    assert env["tool"] == "ssh_show"
    assert env["target"] == "edge-fw-b"
    assert env["ok"] is True
    assert env["format"] == "text"
    assert "lifetime" in env["data"].lower()
    assert any(s["key"] == "phase2_lifetime_seconds" and s["value"] == 3600 for s in env["signals"])


def test_ssh_show_running_config_is_per_device():
    a = _envelope(handle_tools_call({
        "name": "ssh_show",
        "arguments": {"target": "edge-fw-a", "command": "show running-config | section crypto ipsec"},
    }))
    b = _envelope(handle_tools_call({
        "name": "ssh_show",
        "arguments": {"target": "edge-fw-b", "command": "show running-config | section crypto ipsec"},
    }))
    assert "28800" in a["data"]  # edge-fw-a
    assert "3600" in b["data"]   # edge-fw-b (the mismatch)


def test_prometheus_query_returns_matrix():
    env = _envelope(handle_tools_call({
        "name": "prometheus_query",
        "arguments": {"target": "prometheus.mon.internal", "query": "vpn_tunnel_up", "type": "range"},
    }))
    assert env["format"] == "json"
    assert env["data"]["status"] == "success"
    assert env["data"]["data"]["resultType"] == "matrix"


def test_alertmanager_lists_firing_alerts():
    env = _envelope(handle_tools_call({
        "name": "alertmanager_alerts",
        "arguments": {"target": "alertmanager.mon.internal"},
    }))
    names = {a["labels"]["alertname"] for a in env["data"]["alerts"]}
    assert names == {"BGPNeighborDown", "VPNTunnelFlapping"}


def test_logs_query_returns_timeline():
    env = _envelope(handle_tools_call({
        "name": "logs_query",
        "arguments": {"target": "loki.mon.internal", "query": '{job="netsyslog"}'},
    }))
    assert "BGP" in env["data"]
    assert any(s["key"] == "reset_after_rekey_seconds" for s in env["signals"])


def test_snmp_walk_returns_interfaces():
    env = _envelope(handle_tools_call({
        "name": "snmp_walk",
        "arguments": {"target": "edge-fw-b", "oid": "1.3.6.1.2.1.2.2.1"},
    }))
    assert env["format"] == "json"
    assert "interfaces" in env["data"]


def test_unknown_tool_is_error():
    result = handle_tools_call({"name": "reboot_everything", "arguments": {}})
    assert result["isError"] is True


def test_unknown_target_is_error_and_lists_known():
    result = handle_tools_call(
        {"name": "ssh_show", "arguments": {"target": "core-router-99", "command": "show version"}}
    )
    assert result["isError"] is True
    assert "edge-fw-a" in result["content"][0]["text"]


def test_allowlist_refusal_is_error():
    result = handle_tools_call(
        {"name": "ssh_show", "arguments": {"target": "edge-fw-b", "command": "configure terminal"}}
    )
    assert result["isError"] is True
    assert "deny-list" in result["content"][0]["text"]


def test_wrong_endpoint_kind_is_error():
    # prometheus_query against an alertmanager endpoint must not silently work.
    result = handle_tools_call({
        "name": "prometheus_query",
        "arguments": {"target": "alertmanager.mon.internal", "query": "up"},
    })
    assert result["isError"] is True


def test_missing_required_arg_is_error():
    result = handle_tools_call({"name": "ssh_show", "arguments": {"target": "edge-fw-b"}})
    assert result["isError"] is True
