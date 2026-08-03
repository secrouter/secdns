# secdns — small authoritative internal DNS for closed networks

**Zero dependencies. Standard library only.** secdns serves an internal zone so the SecRouter
suite's components resolve each other by name across hosts — and forwards everything else
upstream, or **refuses** it on a fully closed network. It exists so a multi-host deployment
has real name resolution instead of scattered `/etc/hosts` edits.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What it does

- **Authoritative** for one internal zone (default `sec.internal`), answering `A` / `AAAA` /
  `TXT` from a simple zone file. Names inside the zone that don't exist get `NXDOMAIN`; names
  that exist without the asked type get `NODATA` — correct resolver behavior.
- **Forwards** non-internal queries to upstream resolvers, or **refuses** them when no
  upstream is configured (the closed-network default — no lookups leak out).
- **UDP + TCP** on port 53 (TCP length-framed per RFC 1035).
- **Live reload** — regenerate the zone and `kill -HUP` (or click *Reload* in the console);
  no downtime.
- **Status console** — a tiny HTTP page with the served records and live query stats, plus
  `/health` for probes.

In the suite, SecDeploy generates the zone file from your `topology.toml` (one record per
component → the address of the resource hosting it), so addressing stays correct whether two
components share a host or sit on opposite ends of the enclave.

## Quickstart

```bash
uv sync
cp zones/secdns.zone.example zones/secdns.zone     # or let SecDeploy generate it
uv run secdns check-zone --zone zones/secdns.zone  # parse + print records (no network)

# serve (port 53 needs root; use a high port for local testing)
uv run secdns serve --domain sec.internal --zone zones/secdns.zone \
  --upstream 1.1.1.1 --port 5353

# resolve against it
dig @127.0.0.1 -p 5353 secrouter.sec.internal
```

Open the console at `http://127.0.0.1:47053` for status + reload.

## Zone file

One record per line — `<name> <type> <value>` — with `#` comments. Names may be short
(relative to the zone) or full FQDNs:

```
secrouter   A   10.0.0.5
secllm      A   10.0.0.6
# _acme-challenge.secrouter  TXT  "token"    # (future: SecCert DNS-01)
```

## Configuration

Flags override environment variables:

| Flag | Env | Default | |
|---|---|---|---|
| `--domain` | `SECDNS_DOMAIN` | `sec.internal` | authoritative zone |
| `--zone` | `SECDNS_ZONE` | `zones/secdns.zone` | zone file |
| `--upstream` | `SECDNS_UPSTREAM` | *(none → refuse)* | comma-separated forwarders |
| `--bind` / `--port` | `SECDNS_BIND` / `SECDNS_PORT` | `0.0.0.0` / `53` | DNS listener |
| `--admin-bind` / `--admin-port` | `SECDNS_ADMIN_BIND` / `SECDNS_ADMIN_PORT` | `127.0.0.1` / `47053` | console |
| `--ttl` | `SECDNS_TTL` | `60` | answer TTL |
| `--no-forward` | `SECDNS_NO_FORWARD` | forward on | refuse non-internal queries |

## Tests

```bash
uv run pytest
```

Covers the wire-format codec, zone loading, resolver decisions (authoritative / NODATA /
NXDOMAIN / forward / refuse), live UDP + TCP round-trips, and the console.

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe.
