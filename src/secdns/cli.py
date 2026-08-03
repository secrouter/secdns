"""``secdns`` command-line entrypoint.

  secdns serve        run the authoritative + forwarding server (default) and the console
  secdns check-zone   parse the zone file and print its records (no network)

Flags override environment variables (see :mod:`secdns.config`).
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

from .config import Config, _split
from .console import Console
from .resolver import Resolver
from .server import DNSServer
from .zone import Zone


def _config_from(args) -> Config:
    c = Config.from_env()
    if args.domain:
        c.domain = args.domain.rstrip(".").lower()
    if args.zone:
        c.zone_file = Path(args.zone)
    if args.upstream is not None:
        c.upstream = _split(args.upstream)
    if getattr(args, "bind", None):
        c.bind = args.bind
    if getattr(args, "port", None):
        c.port = args.port
    if getattr(args, "admin_bind", None):
        c.admin_bind = args.admin_bind
    if getattr(args, "admin_port", None):
        c.admin_port = args.admin_port
    if getattr(args, "ttl", None):
        c.ttl = args.ttl
    if getattr(args, "no_forward", False):
        c.forward = False
    return c


def cmd_check_zone(args) -> int:
    c = _config_from(args)
    zone = Zone.load(c.zone_file, c.domain, c.ttl)
    print(f"zone {c.domain}: {zone.count} record(s) from {c.zone_file}")
    for name, rtype, value in zone.entries():
        print(f"  {name:<34} {rtype:<5} {value}")
    return 0


def cmd_serve(args) -> int:
    c = _config_from(args)
    resolver = Resolver(c)
    try:
        dns = DNSServer(resolver, bind=c.bind, port=c.port)
    except PermissionError:
        print(f"secdns: binding {c.bind}:{c.port} needs privileges — run as root or use "
              f"--port >1024 (e.g. 5353)", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"secdns: cannot bind {c.bind}:{c.port}: {exc}", file=sys.stderr)
        return 1
    console = Console(resolver, bind=c.admin_bind, port=c.admin_port)
    dns.start()
    console.start()
    fwd = f"→ {', '.join(c.upstream)}" if (c.forward and c.upstream) else "(closed: refuse)"
    print(f"secdns: authoritative for {c.domain} — {resolver.zone.count} records on "
          f"{c.bind}:{dns.udp_port} udp+tcp; forwarding {fwd}")
    print(f"secdns: console http://{c.admin_bind}:{console.port}")

    stop = threading.Event()
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: print(
            f"secdns: reloaded zone — {resolver.reload()} records"))
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()
    dns.stop()
    console.stop()
    print("secdns: stopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secdns", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd")

    def _common(sp):
        sp.add_argument("--domain", help="authoritative zone (default: env SECDNS_DOMAIN or sec.internal)")
        sp.add_argument("--zone", help="zone file path (default: env SECDNS_ZONE or zones/secdns.zone)")
        sp.add_argument("--upstream", help="comma-separated upstream resolvers for non-internal names")
        sp.add_argument("--ttl", type=int, help="answer TTL in seconds (default 60)")

    sp_serve = sub.add_parser("serve", help="run the DNS server + console")
    _common(sp_serve)
    sp_serve.add_argument("--bind", help="DNS listen address (default 0.0.0.0)")
    sp_serve.add_argument("--port", type=int, help="DNS port (default 53; use >1024 unprivileged)")
    sp_serve.add_argument("--admin-bind", dest="admin_bind", help="console address (default 127.0.0.1)")
    sp_serve.add_argument("--admin-port", dest="admin_port", type=int, help="console port (default 47053)")
    sp_serve.add_argument("--no-forward", dest="no_forward", action="store_true",
                          help="refuse non-internal queries instead of forwarding (closed network)")
    sp_serve.set_defaults(fn=cmd_serve)

    sp_check = sub.add_parser("check-zone", help="parse the zone file and print records")
    _common(sp_check)
    sp_check.set_defaults(fn=cmd_check_zone)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # No subcommand (or leading flags) → default to `serve`.
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["serve"] + argv
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except (ValueError, FileNotFoundError) as exc:
        print(f"secdns: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
