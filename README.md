# SlimX-NetOps

The bounded, **read-only** network telemetry bridge of the SlimX platform. It exposes a small set
of read-only network/observability reads as **MCP-over-HTTP tools** so SlimX-AI ControlRoom's NetOps
agent pack can *investigate* incidents — collect evidence, explain root causes — without ever being
able to change a device.

It is one job only. It does **not** own connector registries, approval policy, credentials-in-app,
or UI — those stay in ControlRoom, which reaches this bridge as a remote MCP connector through its
one bounded MCP boundary. This mirrors the platform split used by
[`SlimX-MCP`](../SlimX-MCP) and [`SlimX-Agent`](../SlimX-Agent).

## Layering

| Concern | Owner |
| --- | --- |
| Read-only device/telemetry clients (SSH show, SNMP GET/WALK, Prometheus, Alertmanager, logs) | **SlimX-NetOps** (this repo) |
| Command/OID allowlist + deny patterns (the safety layer) | **SlimX-NetOps** (`allowlist.py`) |
| Device inventory + credentials (env / mounted secrets) + the target-egress boundary | **SlimX-NetOps** (`inventory.py`) |
| Connector registry, approval/grant policy, audit, UI | **ControlRoom** |
| Agent orchestration, evidence/synthesis | **ControlRoom** + **SlimX-Agent** |

## Read-only guarantee

Read-only is **structural**, not just convention:

- `ssh_show` runs one allowlisted `show`/`display` command via netmiko `send_command` — config mode
  is never entered, mutating verbs are refused, shell metacharacters and output redirection are
  rejected (`allowlist.py::validate_show_command`).
- SNMP issues GET/WALK PDUs only (never SET); OIDs must sit under an allowlisted read-only MIB root.
- Prometheus/Alertmanager/Loki calls are HTTP GETs to read endpoints whose **paths this bridge
  constructs** — a caller-supplied query can never change the endpoint path.
- The bridge only reaches targets in its **inventory** (the egress boundary). An unknown target is
  refused.

> `allowlist.py` is security-critical. Do not enable live mode against real gear before it has had a
> security review, and keep it in code (not env) so it stays auditable.

## Tools

`ssh_show` · `snmp_get` · `snmp_walk` · `prometheus_query` · `alertmanager_alerts` · `logs_query`.
Each returns the frozen envelope
`{tool, target, command, collected_at, ok, truncated, format, data, signals}` inside MCP
`content[0].json` (plus `structuredContent`). A failure returns `isError: true` with a human message
— never a fake success.

## Modes

- `NETOPS_MODE=fixture` (default) — replays the canonical **"BGP resets after VPN flap"** scenario
  fixtures (`slimx_netops/fixtures/`). No device libraries, no credentials, no infra. This powers
  demos, CI, and ControlRoom's integration tests.
- `NETOPS_MODE=live` — the real read-only clients. Requires the `[live]` extra
  (`pip install slimx-netops[live]`), a real inventory (`NETOPS_INVENTORY`), and credentials.

## Run

```bash
# Docker (fixture mode by default)
docker build -t slimx-netops .
docker run --rm -p 8092:8092 slimx-netops

# Local
pip install -e '.[dev]'
uvicorn slimx_netops.service:app --port 8092
curl -s localhost:8092/health
```

JSON-RPC over `POST /mcp`:

```bash
curl -s localhost:8092/mcp -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tools/call",
  "params":{"name":"ssh_show","arguments":{"target":"edge-fw-b","command":"show crypto ipsec sa"}}
}'
```

## Configuration

| Env | Default | Purpose |
| --- | --- | --- |
| `NETOPS_MODE` | `fixture` | `fixture` or `live`. |
| `NETOPS_INVENTORY` | packaged fixture inventory | Path to the inventory JSON (devices + endpoints). |
| `NETOPS_FIXTURES_DIR` | packaged `fixtures/` | Fixture directory for fixture mode. |
| `SLIMX_NETOPS_INTERNAL_TOKEN` | *(unset)* | When set, `/mcp` requires `Authorization: Bearer <token>` (constant-time). Unset = auth off (local-first). |
| `NETOPS_MAX_OUTPUT_BYTES` | `256000` | CLI/log output cap (sets `truncated`). |
| `NETOPS_SSH_TIMEOUT_SECONDS` / `NETOPS_SNMP_TIMEOUT_SECONDS` / `NETOPS_HTTP_TIMEOUT_SECONDS` | `20` / `10` / `15` | Per-read timeouts. |
| `NETOPS_LOGS_MAX_LINES` | `5000` | Hard cap for `logs_query`. |

Credentials in the inventory are `${ENV_VAR}` placeholders resolved at call time — never stored in
the file, never returned to callers.

## ControlRoom wiring

Add SlimX-NetOps as a remote MCP connector (`category: netops`, `serverUrl:
http://slimx-netops:8092/mcp`, bearer `${SLIMX_NETOPS_INTERNAL_TOKEN}`) and list the tools in the
connector's `allowedTools`. The agent reaches them via the hard-gated `mcp_call` step (grant
`mcp_tools`). See `docs/netops/contract.md` in the ControlRoom repo. Compose runs it under the
`netops` profile; add `slimx-netops` to `MCP_ALLOWED_INTERNAL_HOSTS`.

## Tests

```bash
pip install -e '.[dev]'
ruff check . && pytest -q
```
