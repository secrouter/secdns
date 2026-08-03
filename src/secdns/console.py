"""Status console — a tiny HTTP server for humans and health checks.

Routes:
  GET  /          HTML status page (zone, upstreams, live query stats) + a Reload button
  GET  /health    JSON liveness ({status, records, queries}) — for probes / `status`
  GET  /records   JSON dump of the served records
  POST /reload    re-read the zone file and return the new record count

Bound to localhost by default (see :class:`~secdns.config.Config`). Standard library only.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .resolver import Resolver

_PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>secdns — {domain}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0 auto;
        max-width: 820px; padding: 2rem 1.25rem; }}
 h1 {{ font-size: 1.3rem; margin: 0 0 .25rem; }}
 .sub {{ opacity: .65; margin: 0 0 1.5rem; }}
 .grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(120px,1fr)); gap: .75rem;
         margin-bottom: 1.5rem; }}
 .card {{ border: 1px solid #8883; border-radius: 8px; padding: .6rem .8rem; }}
 .card b {{ font-size: 1.5rem; display: block; }}
 .card span {{ opacity: .65; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
 table {{ width: 100%; border-collapse: collapse; }}
 th, td {{ text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #8882; }}
 th {{ opacity: .6; font-weight: 600; }}
 button {{ font: inherit; padding: .45rem .9rem; border-radius: 7px; border: 1px solid #8886;
          background: #8881; cursor: pointer; }}
 .row {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }}
 .ok {{ color: #2e9e44; }}
</style>
<h1>secdns <span class="ok">●</span></h1>
<p class="sub">authoritative zone <b>{domain}</b> · forwarding {forward} · ttl {ttl}s</p>
<div class="grid">
 <div class="card"><b>{records}</b><span>records</span></div>
 <div class="card"><b>{queries}</b><span>queries</span></div>
 <div class="card"><b>{authoritative}</b><span>authoritative</span></div>
 <div class="card"><b>{forwarded}</b><span>forwarded</span></div>
 <div class="card"><b>{nxdomain}</b><span>nxdomain</span></div>
 <div class="card"><b>{refused}</b><span>refused</span></div>
</div>
<div class="row"><button onclick="reload()">Reload zone</button><span id="msg"></span></div>
<table><thead><tr><th>name</th><th>type</th><th>value</th></tr></thead><tbody>
{rows}
</tbody></table>
<script>
async function reload() {{
  const m = document.getElementById('msg'); m.textContent = 'reloading…';
  const r = await fetch('/reload', {{method:'POST'}}); const j = await r.json();
  m.textContent = '✓ ' + j.records + ' records'; setTimeout(() => location.reload(), 500);
}}
</script>
"""


def _handler_factory(resolver: Resolver):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence default stderr access log
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:
            if self.path in ("/health", "/healthz"):
                self._json(200, {"status": "ok", "domain": resolver.config.domain,
                                 "records": resolver.zone.count,
                                 "queries": resolver.stats["queries"]})
            elif self.path == "/records":
                self._json(200, {"records": [
                    {"name": n, "type": t, "value": v} for n, t, v in resolver.zone.entries()
                ]})
            elif self.path == "/":
                self._send(200, self._render().encode(), "text/html; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path == "/reload":
                count = resolver.reload()
                self._json(200, {"status": "reloaded", "records": count})
            else:
                self._json(404, {"error": "not found"})

        def _render(self) -> str:
            rows = "\n".join(
                f"<tr><td>{n}</td><td>{t}</td><td>{v}</td></tr>"
                for n, t, v in resolver.zone.entries()
            ) or '<tr><td colspan="3" style="opacity:.6">(empty zone)</td></tr>'
            s = resolver.stats
            return _PAGE.format(
                domain=resolver.config.domain,
                forward="on" if (resolver.config.forward and resolver.config.upstream) else "off",
                ttl=resolver.config.ttl, records=resolver.zone.count,
                queries=s["queries"], authoritative=s["authoritative"],
                forwarded=s["forwarded"], nxdomain=s["nxdomain"], refused=s["refused"],
                rows=rows,
            )

    return Handler


class Console:
    """The admin HTTP server; ``start`` runs it in a daemon thread."""

    def __init__(self, resolver: Resolver, bind: str = "127.0.0.1", port: int = 47053) -> None:
        self.httpd = ThreadingHTTPServer((bind, port), _handler_factory(resolver))
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
