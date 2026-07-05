from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _fixture_mode(monkeypatch):
    """Every test runs in fixture mode with fresh caches so env changes take effect."""
    monkeypatch.setenv("NETOPS_MODE", "fixture")
    monkeypatch.delenv("NETOPS_INVENTORY", raising=False)
    monkeypatch.delenv("SLIMX_NETOPS_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("NETOPS_ENABLE_WRITE", raising=False)  # writes off by default
    monkeypatch.delenv("NETOPS_FIXTURE_SIMULATE_WRITES", raising=False)  # reflect writes by default
    _clear_caches()
    yield
    _clear_caches()


def _clear_caches() -> None:
    from slimx_netops import clients, config, inventory

    config.get_settings.cache_clear()
    inventory._raw_inventory.cache_clear()
    clients._FIXTURE_WRITE_STATE.clear()  # process-level write-state simulation must not bleed
