# Status console

secdns serves a small HTTP console alongside the DNS listeners — bound to `127.0.0.1:47053`
by default (`--admin-bind` / `--admin-port`). It is for operators and health probes; it does
not answer DNS.

## Pages & endpoints

| Method | Path | Returns |
|---|---|---|
| `GET` | `/` | HTML status page: zone name, forwarding state, TTL, record count, live query stats, the served records, and a **Reload zone** button |
| `GET` | `/health` | JSON `{status, domain, records, queries}` — for liveness probes |
| `GET` | `/records` | JSON dump of the served records (`name`, `type`, `value`) |
| `POST` | `/reload` | re-read the zone file; returns `{status, records}` |

## Query statistics

The status page and `/health` reflect counters the resolver maintains: total `queries`, and
how they were answered — `authoritative`, `forwarded`, `nodata`, `nxdomain`, `refused`, and
`malformed`. They are a quick way to confirm, after a deploy, that internal names are being
answered authoritatively and that nothing unexpected is being forwarded.

## Health check

```bash
curl -s http://127.0.0.1:47053/health
# {"status": "ok", "domain": "sec.internal", "records": 8, "queries": 5}
```

`secdeploy status` uses this endpoint to report secdns health as part of the suite.
