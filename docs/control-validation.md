# Control validation

secdns's compliance posture for audit & accountability (NIST SP 800-171 r2, Family **AU**).
Citation style: bare control IDs with a Family column in this table; `AU-3.3.x` in prose/code.

## Controls

| Family | ID | Requirement | Implementation (file:function) | Evidence command |
|---|---|---|---|---|
| AU | 3.3.1 | Create and retain audit records for lifecycle/administrative events | {mod}`secdns.audit.AuditLogger.record`, called from {mod}`secdns.resolver.Resolver` (`zone.load`, `zone.reload`) and {mod}`secdns.cli` (`server.start`, `server.stop`) | `cat $(secdns audit verify --zone <zone> 2>&1 >/dev/null; echo state/secdns-audit.jsonl)` — or simply read the path printed by `secdns serve` / the `--audit-path` flag |
| AU | 3.3.2 | Ensure actions can be traced to the responsible principal | `principal` field on every record — `"system"` for daemon-initiated events (SIGHUP, startup, shutdown), `"console:<client-ip>"` when a human triggers `POST /reload` through the status console | `secdns audit verify --zone <zone>` then inspect `principal` on each line |
| AU | 3.3.8 | Protect audit information/tooling from unauthorized access, modification, deletion | SHA-256 hash chain (`prevHash`/`hash`, genesis `"GENESIS"`) over canonicalized (sorted-key JSON) records in {mod}`secdns.audit`; log file and directory chmod'd `0o600`/`0o700` at write time; `secdns audit verify` (also importable as `secdns.audit.verify`) detects any edited, reordered, or deleted record | `secdns audit verify --zone <zone>` → `{"ok": true, "checked": N}`, or `{"ok": false, "brokenAtSeq": N}` on tamper |
| AU | 3.3.1 (per-query) | Per-query DNS request logging | **Not implemented — environment-owned, by design.** secdns is a hot-path UDP/TCP resolver; adding synchronous (or even buffered) per-query audit I/O to the answer path would turn a DNS outage risk into an audit-log outage risk, and query volume make a chained JSONL an unsuitable store for it. Query *counts* by outcome (`authoritative`/`nodata`/`nxdomain`/`forwarded`/`refused`/`malformed`) are exposed live and unauthenticated-locally via `GET /health` and the console for operational visibility, but individual queries are not recorded here. A site that needs per-query DNS logs should capture them downstream (e.g. packet capture, a dedicated DNS logging resolver, or the network layer) — outside secdns's trust boundary. | n/a (document this posture, don't fake an event stream for it) |
| AU | 3.3.5 | Correlate audit records across components for suite-wide analysis | Canonical field names (`ts`, `type`, `principal`, `sourceIp`, `target`, `outcome`, `detail`, `prevHash`, `hash`) match the suite-wide audit convention, so secdns's log can be ingested alongside secrouter/secchat/secagent/secllm/secrecorder audit streams without translation | Diff the JSON keys here against another component's `docs/control-validation.md` (or its audit module) |

## What's NOT covered here (config.change)

The current code has no runtime configuration-mutation entry point — no admin API changes
`domain`, `upstream`, `ttl`, or bind addresses while the process is running; the only runtime
mutation is the zone content itself, which the `zone.reload` event above already covers. A
`config.change` event is therefore not emitted. If a future admin API adds live config
mutation, it must emit `config.change` the same way `zone.reload` does, and this table should
be updated rather than silently left stale.

## Shared responsibility

| Owner | Responsibility |
|---|---|
| **secdns** | Lifecycle audit (server start/stop, zone load/reload) with principal attribution and a tamper-evident hash chain; `secdns audit verify` for on-demand verification; at-rest file permission hardening (best-effort, `chmod`). |
| **Environment / operator** | Per-query DNS logging, if required by site policy, at the network or resolver-appliance layer (outside secdns). Forwarding the audit JSONL to a SIEM/log-retention system, and retention policy for it (secdns itself never rotates or prunes the log). Filesystem-level protection (disk encryption, backup, access control) beyond the `chmod` secdns applies at write time. Restricting who can reach the console's `POST /reload` at the network layer — secdns binds the console to `127.0.0.1` by default but does not itself authenticate console requests. |

## Notes

- Audit is **enabled by default** (`SECDNS_AUDIT_ENABLED`, `--no-audit` to disable) and writes
  to a chained JSONL file that defaults to sitting alongside the zone file
  (`<zone_file_dir>/secdns-audit.jsonl`; override with `SECDNS_AUDIT_PATH` / `--audit-path`).
- Writes happen only on the rare lifecycle events above — never per DNS query — so a plain
  synchronous file append is safe here; see `src/secdns/audit.py`'s module docstring for the
  hot-path rationale.
- `detail` is metadata only (record counts, file paths, error strings truncated to 200 chars)
  — it never contains zone record *values* or query content.
