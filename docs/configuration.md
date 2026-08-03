# Configuration

secdns is configured by command-line flags, which override environment variables, which fall
back to built-in defaults. There is no config file — the only stateful input is the
[zone file](zone.md).

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--domain` | `SECDNS_DOMAIN` | `sec.internal` | the authoritative internal zone |
| `--zone` | `SECDNS_ZONE` | `zones/secdns.zone` | path to the zone file |
| `--upstream` | `SECDNS_UPSTREAM` | *(none)* | comma-separated upstream resolvers for non-internal names; empty ⇒ refuse |
| `--bind` | `SECDNS_BIND` | `0.0.0.0` | DNS listen address |
| `--port` | `SECDNS_PORT` | `53` | DNS port (needs privileges below 1024) |
| `--admin-bind` | `SECDNS_ADMIN_BIND` | `127.0.0.1` | console listen address |
| `--admin-port` | `SECDNS_ADMIN_PORT` | `47053` | console port |
| `--ttl` | `SECDNS_TTL` | `60` | TTL (seconds) on answers |
| `--no-forward` | `SECDNS_NO_FORWARD` | *(forward on)* | refuse non-internal queries outright |

## Commands

```
secdns serve        run the server (UDP+TCP) and the console  [default]
secdns check-zone   parse the zone file and print its records (no network)
```

`serve` is the default, so `secdns` with no subcommand starts the server. Running with no
subcommand but with flags (`secdns --port 5353`) also serves.

## Closed-network vs. forwarding

Leave `--upstream` unset for a **fully closed network**: secdns answers internal names and
REFUSEs everything else, so no query escapes the enclave. Set `--upstream 1.1.1.1,9.9.9.9`
(or your site resolvers) when hosts also need to reach the outside world; secdns then relays
non-internal queries and returns the first upstream answer.

## Privileges

Port 53 is privileged. In production secdns runs as a hardened service (see
[deployment](deployment.md)); for local testing use a high port:

```bash
uv run secdns serve --port 5353 --admin-port 47053 --zone zones/secdns.zone --no-forward
dig @127.0.0.1 -p 5353 secrouter.sec.internal
```
