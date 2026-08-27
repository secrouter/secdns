# Changelog

## [Unreleased]

### Fixed
- **Serve DNS even when the console port is unavailable.** `cmd_serve` created the admin
  console unconditionally, so a console-port (`:47053`) conflict — e.g. a stale instance
  still holding it — raised *after* the DNS sockets were already bound, crashing the whole
  server. Under a supervisor that restarts on exit (launchd/systemd) that turned a transient
  collision into a permanent crash-loop. The console is now best-effort: a bind failure
  prints a warning and secdns serves DNS without it. DNS is the critical function and stays up.

## [0.1.0] — secdns

First release of **secdns** — a small, **zero-dependency** authoritative DNS server for
closed networks, the naming layer of the SecRouter suite.

- **Authoritative** for one internal zone (`A`/`AAAA`/`TXT` from a generated zone file);
  **forwards** everything else upstream, or **refuses** it when no upstream is configured
  (the closed-network default).
- **UDP + TCP** on port 53, with the DNS wire-format codec (header, question, resource
  records, name compression) hand-rolled in `secdns.message` — no third-party parser in the
  trust boundary.
- **Live zone reload** via `SIGHUP` or the status console, no downtime.
- **Status console** — an HTTP page with served records and live query stats, plus
  `/health` for probes.
- 20 tests, including live UDP+TCP round-trips and the console, and Sphinx docs.
