"""Service mode: /health, the JSON-RPC /mcp surface, and internal-token auth."""

from __future__ import annotations

from fastapi.testclient import TestClient

from slimx_netops.service import app

client = TestClient(app)


def _rpc(method: str, params: dict | None = None, headers: dict | None = None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=headers or {})


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "slimx-netops"
    assert data["mode"] == "fixture"
    assert data["auth_enabled"] is False


def test_tools_list_over_jsonrpc():
    resp = _rpc("tools/list")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] == 1
    names = {t["name"] for t in payload["result"]["tools"]}
    assert "ssh_show" in names and len(names) == 6


def test_tools_call_over_jsonrpc():
    resp = _rpc(
        "tools/call",
        {"name": "ssh_show", "arguments": {"target": "edge-fw-b", "command": "show crypto ipsec sa"}},
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert not result.get("isError")
    assert result["content"][0]["json"]["target"] == "edge-fw-b"


def test_initialize_is_polite_noop():
    resp = _rpc("initialize")
    assert resp.status_code == 200
    assert resp.json()["result"]["serverInfo"]["name"] == "slimx-netops"


def test_unknown_method_404():
    resp = _rpc("resources/subscribe")
    assert resp.status_code == 404


def test_auth_required_when_token_set(monkeypatch):
    monkeypatch.setenv("SLIMX_NETOPS_INTERNAL_TOKEN", "s3cr3t")
    # No / wrong header → 401
    assert _rpc("tools/list").status_code == 401
    assert _rpc("tools/list", headers={"Authorization": "Bearer wrong"}).status_code == 401
    # Correct header → 200
    ok = _rpc("tools/list", headers={"Authorization": "Bearer s3cr3t"})
    assert ok.status_code == 200
    # /health stays open and reports auth_enabled
    assert client.get("/health").json()["auth_enabled"] is True
